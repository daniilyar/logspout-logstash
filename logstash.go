package logstash

import (
	"encoding/json"
	"errors"
	_ "expvar"
	"log"
	"net"
	"strings"
	"regexp"
	"strconv"
	"time"
	"os"

        "github.com/fsouza/go-dockerclient"
	"github.com/gliderlabs/logspout/router"
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/exp"
	"github.com/daniilyar/logspout-logstash/multiline"
        "gopkg.in/fatih/pool.v2"
)

var (
	logMeter = metrics.NewMeter()
)

func init() {
	router.AdapterFactories.Register(NewLogstashAdapter, "logstash")
	exp.Exp(metrics.DefaultRegistry)
	metrics.Register("logstash_message_rate", logMeter)
}

type newMultilineBufferFn func() (multiline.MultiLine, error)

// LogstashAdapter is an adapter that streams TCP JSON to Logstash.
type LogstashAdapter struct {
	connectionPool pool.Pool
	route	   *router.Route
	transport  router.AdapterTransport
	cache	   map[string]*multiline.MultiLine
	cacheTTL	time.Duration
	cachedLines metrics.Gauge
	mkBuffer	newMultilineBufferFn
        containerTags map[string][]string
	multilineApps []string
}

type ControlCode int

const (
	Continue ControlCode = iota
	Quit
)

// NewLogstashAdapter creates a LogstashAdapter with UDP as the default transport.
func NewLogstashAdapter(route *router.Route) (router.LogAdapter, error) {

	log.Println("Creating Logstash adapter ...")

	transport, found := router.AdapterTransports.Lookup(route.AdapterTransport("tcp"))
	if !found {
	    return nil, errors.New("unable to find adapter: " + route.Adapter)
	}

	patternString := getopt(route.Options, "pattern", "PATTERN", `^\[`)
	groupWith := getopt(route.Options, "group_with", "GROUP_WITH", "previous")
	negateStr := getopt(route.Options, "negate", "NEGATE", "true")
	separator := getopt(route.Options, "separator", "SEPARATOR", "\n")

	maxLines, err := strconv.Atoi(route.Options["max_lines"])
	if err != nil {
	    maxLines = 0
	}

	cacheTTL, err := time.ParseDuration(route.Options["cache_ttl"])
	if err != nil {
	    cacheTTL = 10 * time.Second
	}

	cachedLines := metrics.NewGauge()
	metrics.Register(route.ID+"_cached_lines", cachedLines)

	log.Println("Created Logstash adapter with following settings:")
	log.Println("Logstash-adapter: multiline options: [ pattern=" + string(patternString) + ", groupWith=" + string(groupWith) + ", negate=" + negateStr + ", separator=" + string(separator), ", maxLines=" + string(maxLines) + ", cacheTTL=" + string(cacheTTL) + " ]")

	multilineApps := strings.Split(os.Getenv("APPS_WITH_MULTILINE_LOGS"),",")

	connectionPool := createConnectionPool(transport, route)

	return &LogstashAdapter{
		connectionPool: connectionPool,
		route:	     route,
		transport:   transport,
		cache:	     make(map[string]*multiline.MultiLine),
		cacheTTL:	 cacheTTL,
		cachedLines: cachedLines,
		mkBuffer: func() (multiline.MultiLine, error) {
			return multiline.NewMultiLine(
				&multiline.MultilineConfig{
					Pattern:   regexp.MustCompile(patternString),
					GroupWith: groupWith,
					Negate:	   negateStr == "true",
					Separator: &separator,
					MaxLines:  maxLines,
				})
		},
		containerTags: make(map[string][]string),
		multilineApps: multilineApps,
	}, nil
}

func createConnectionPool (transport router.AdapterTransport, route *router.Route) pool.Pool {
	connectionPoolFactory := func()(net.Conn, error){ return getConnection(transport, route) }

	// create a new channel based pool with an initial capacity of 1 and maximum capacity of 10. The factory will create 1 initial connections and put them into the pool.
	connectionPool, err := pool.NewChannelPool(1, 5, connectionPoolFactory)
	if err != nil {
	    log.Fatal("Logstash-adapter: Can't create connection pool", err)
	    os.Exit(8)
	}

	return connectionPool
}

func getConnection(transport router.AdapterTransport, route *router.Route) (net.Conn, error) {

	tries := uint(13)

	try := uint(1)
	for {
		conn, err := transport.Dial(route.Address, route.Options)
		if err == nil && conn != nil {
			if try > 1 {
			    log.Println("Logstash-adapter: connect: successful after " + strconv.FormatUint(uint64(try), 10) + " trie(s)")
			}
			return conn, nil
		} else {
		    log.Println("Logstash-adapter: error connecting to Logstash, reconnecting (" + strconv.FormatUint(uint64(try), 10) + ")", err)
		}

		if try > tries {
		    log.Fatal("Can't connect to Logstash after 12 tries")
		    os.Exit(3)
		}

		time.Sleep((1 << try) * 30 * time.Millisecond)
		try++
	}
}

func (a *LogstashAdapter) lookupBuffer(msg *router.Message) *multiline.MultiLine {
	key := msg.Container.ID + msg.Source
	if a.cache[key] == nil {
		ml, _ := a.mkBuffer()
		a.cache[key] = &ml
	}
	return a.cache[key]
}

// Stream implements the router.LogAdapter interface.
func (a *LogstashAdapter) Stream(logstream chan *router.Message) {
	cacheTicker := time.NewTicker(a.cacheTTL).C

	for {
		msgs, ccode := a.readMessages(logstream, cacheTicker)
		a.sendMessages(msgs)

		switch ccode {
		case Continue:
			continue
		case Quit:
			return
		}
	}
}

func (a *LogstashAdapter) readMessages(
	logstream chan *router.Message,
	cacheTicker <-chan time.Time) ([]*router.Message, ControlCode) {
	select {
	case t := <-cacheTicker:
		return a.expireCache(t), Continue
	case msg, ok := <-logstream:
		if ok {

		    containerType := getEnvVar(msg.Container.Config.Env, "TYPE")
		    if containerType == "" {
			containerType = "<unknown>"
		    }

		    if stringIn(containerType, a.multilineApps) {
			// log.Println("Logstash-adapter: APP of type " + string(containerType) + " has multiline logs, buffering message ...")
				    return a.bufferMessage(msg), Continue
		    } else {
			// log.Println("Logstash-adapter: APP of type " + string(containerType) + " has not multiline logs, not buffering message ...")
			return []*router.Message{msg}, Continue
		    }
		} else {
		    return a.flushPendingMessages(), Quit
		}
	}
}

func stringIn(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func (a *LogstashAdapter) bufferMessage(msg *router.Message) []*router.Message {
	msgOrNil := a.lookupBuffer(msg).Buffer(msg)

	if msgOrNil == nil {
		return []*router.Message{}
	} else {
		return []*router.Message{msgOrNil}
	}
}

func (a *LogstashAdapter) expireCache(t time.Time) []*router.Message {
	var messages []*router.Message
	var linesCounter int64 = 0

	for id, buf := range a.cache {
		linesCounter += int64(buf.PendingSize())
		msg := buf.Expire(t, a.cacheTTL)
		if msg != nil {
			messages = append(messages, msg)
			delete(a.cache, id)
		}
	}

	a.cachedLines.Update(linesCounter)

	return messages
}

func (a *LogstashAdapter) flushPendingMessages() []*router.Message {
	var messages []*router.Message

	for _, buf := range a.cache {
		msg := buf.Flush()
		if msg != nil {
			messages = append(messages, msg)
		}
	}

	return messages
}

func (a *LogstashAdapter) sendMessages(msgs []*router.Message) {
	for _, msg := range msgs {
		err := a.sendMessage(msg)
		if err != nil {
		    log.Fatal("Logstash-adapter: error sending message to logstash - ", err)
		    os.Exit(3)
		}
	}

	msgCount := len(msgs)
	if msgCount > 0 {
	    log.Println("Logstash-adapter: " + strconv.Itoa(msgCount) + " message(s) sent")
	    logMeter.Mark(int64(msgCount))
	}
}

func (a *LogstashAdapter) sendMessage(msg *router.Message) error {

	buff, err := serialize(msg, a)
	if err != nil {
	    return err
	}

	_, err = write(a, buff, 13)
	if err != nil {
	    log.Fatal("Logstash-adapter: cannot write message to logstash after 15 tries - ", err)
	    os.Exit(6)
	}

	return nil
}

func serialize(msg *router.Message, a *LogstashAdapter) ([]byte, error) {

	var js []byte
	var jsonMsg map[string]interface{}

	tags := GetContainerTags(msg.Container, a)

	err := json.Unmarshal([]byte(msg.Data), &jsonMsg)

	if err != nil {
		// the message is not in JSON make a new JSON message
		msg := LogstashMessage {
			Message: msg.Data,
			Logtype: getEnvVar(msg.Container.Config.Env, "TYPE"),
			// App: getEnvVar(msg.Container.Config.Env, "APP"),
			DockerContainerID: msg.Container.ID[0:6], // take only first 6 symbols of container ID
			KubernetesPod: msg.Container.Config.Labels["io.kubernetes.pod.name"],
			KubernetesContainer: msg.Container.Config.Labels["io.kubernetes.container.name"],
			KubernetesNamespace: msg.Container.Config.Labels["io.kubernetes.pod.namespace"],
			Stream:  msg.Source,
			Tags:	tags,
		}
		js, err = json.Marshal(msg)
		if err != nil {
			return nil, err
		}
	} else {
		// the message is already in JSON just add the docker specific fields as a nested structure
		// jsonMsg["tags"] = tags
		// jsonMsg["stream"] = msg.Source

		js, err = json.Marshal(jsonMsg)
		if err != nil {
			return nil, err
		}
	}

	return js, nil
}

// LogstashMessage is a simple JSON input to Logstash.
type LogstashMessage struct {
	Message	string		   `json:"message"`
	Stream	 string		   `json:"stream"`
	Logtype	string		   `json:"log_type"`
	DockerContainerID string   `json:"container_id"`
	KubernetesPod   string     `json:"k8_pod"`
	KubernetesContainer string `json:"k8_container"`
	KubernetesNamespace string `json:"k8_namespace"`
	Tags	   []string        `json:"tags"`
}

func write (a *LogstashAdapter, buff []byte, tries uint) (int, error) {

	conn := getConnectionFromPool(a)

	try := uint(1)
	for {
		var n int
		n, err := conn.Write([]byte(string(buff) + "\n"))
		if err == nil {
			if try > 1 {
				log.Println("Logstash-adapter: message send: retry successful after " + strconv.FormatUint(uint64(try), 10) + " trie(s)")
			}
			return n, nil
		} else {
			if strings.Contains(err.Error(), "broken pipe") {
				log.Println("Logstash-adapter: broken pipe error occured. Re-initializing Logstash connection ...")

				// close and re-create Logstash connection pool
				a.connectionPool.Close()
				a.connectionPool = createConnectionPool(a.transport, a.route)

				// re-create the current connection
				conn = getConnectionFromPool(a)
			} else {
				log.Println("Logstash-adapter: Error sending data to Logstash, retrying message send ("+strconv.FormatUint(uint64(try), 10)+")", err)
			}
		}

		if try > tries {
			return n, err
		}

		time.Sleep((1 << try) * 30 * time.Millisecond)
		try++
	}

	if conn != nil {
	    conn.Close()
	}

	return 0, nil
}

func getConnectionFromPool(a *LogstashAdapter) net.Conn {
	conn, err := a.connectionPool.Get()
	if err != nil {
	    log.Fatal("Cannot get connection from pool - ", err)
	    os.Exit(10)
	}
	return conn
}

func getEnvVar(env []string, key string) string {
  key_equals := key + "="
  for _, value := range env {
	if strings.HasPrefix(value, key_equals)  {
	  return value[len(key_equals):]
	}
  }
  return ""
}

func getopt(options map[string]string, optkey string, envkey string, default_value string) (value string) {
	value = options[optkey]
	if value == "" {
		value = os.Getenv(envkey)
		if value == "" {
			value = default_value
		}
	}
	return
}

// Get container tags configured with the environment variable LOGSTASH_TAGS
func GetContainerTags(c *docker.Container, a *LogstashAdapter) []string {
	if tags, ok := a.containerTags[c.ID]; ok {
		return tags
	}
 
	var tags = []string{}
	for _, e := range c.Config.Env {
		if strings.HasPrefix(e, "LOGSTASH_TAGS=") {
			tags = strings.Split(strings.TrimPrefix(e, "LOGSTASH_TAGS="), ",")
			break
		}
	}
 
	a.containerTags[c.ID] = tags
	return tags
}
