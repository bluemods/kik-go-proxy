package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bluemods/kik-go-proxy/crypto"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
)

const (
	// Max size that a batch of acks can be
	MAX_QOS_BATCH_SIZE = 50
)

var (
	// Allow 10 messages in 10s
	RATE_LIMIT       = rate.Every(10 * time.Second)
	RATE_LIMIT_BURST = 10

	// Auto remove key from map after 15s
	LRU_EXPIRE_TIME = time.Second * 15
)

// Simple rate limiter that blocks stanzas when sent too quickly.
// The server will drop spam before it reaches the client, and ack it via QoS when necessary.
// This struct makes no guarantees when it comes to thread safety.
type KikRateLimiter struct {
	// Map key is the correspondent ID ("from" attribute in message stanza)
	ChatIds expirable.LRU[string, *rate.Limiter]

	// Messages currently blocked and waiting to be acked.
	BlockedMessages []SimpleKikMessage
}

// Bare minimum struct for a Kik message.
// Only contains the fields required for acking the stanza via QoS.
type SimpleKikMessage struct {
	Id            string
	Bin           string
	Correspondent string
	IsGroup       bool
}

type QoSMessageSorter struct {
	Ids           []string
	Bin           string
	Correspondent string
	_isGroup      bool
}

func (q *QoSMessageSorter) IsActuallyAGroup() bool {
	return q._isGroup && q.Bin != q.Correspondent && strings.HasSuffix(q.Bin, "_g@groups.kik.com")
}

// Map key used for sorting the messages for the QoS stanza.
func (m *SimpleKikMessage) GetMapKey() string {
	return m.Bin + m.Correspondent + strconv.FormatBool(m.IsGroup)
}

func (i *KikRateLimiter) ProcessMessage(kikConn net.Conn, message Node) bool {
	if message.Name != "message" {
		return false
	}
	correspondent, exists := message.Attributes["from"]
	if !exists {
		return false
	}

	limiter, exists := i.ChatIds.Get(correspondent)
	if !exists {
		limiter = rate.NewLimiter(RATE_LIMIT, RATE_LIMIT_BURST)
		i.ChatIds.Add(correspondent, limiter)
		// Allow will return true on first invocation, exit early
		limiter.Allow()
		return false
	}
	blocked := !limiter.Allow()
	if blocked {
		// Rate limit hit, let's mitigate.
		// Check for 'qos' flag in message...

		// log.Println("Rejecting spam from " + correspondent + ", size: " + strconv.Itoa(len(i.BlockedMessages)))

		qos := false
		for _, kik := range message.FindAll("kik") {
			if kik.Get("qos") != "false" {
				qos = true
				break
			}
		}

		if qos {
			bin := correspondent
			g := message.FindLast("g")
			isGroup := false
			if g != nil && g.HasAttribute("jid") {
				bin = g.Get("jid")
				isGroup = true
			}

			message := SimpleKikMessage{
				Id:            message.Get("id"),
				Bin:           bin,
				Correspondent: correspondent,
				IsGroup:       isGroup,
			}
			i.BlockedMessages = append(i.BlockedMessages, message)

			if len(i.BlockedMessages) >= MAX_QOS_BATCH_SIZE {
				i.FlushMessages(kikConn)
				i.BlockedMessages = i.BlockedMessages[:0] // clear
			}
		}
	}
	return blocked
}

func (i *KikRateLimiter) FlushMessages(kikConn net.Conn) {
	temp := make(map[string]*QoSMessageSorter)

	for _, message := range i.BlockedMessages {
		mapKey := message.GetMapKey()
		sorter, found := temp[mapKey]
		if found {
			sorter.Ids = append(sorter.Ids, message.Id)
		} else {
			ids := make([]string, 1)
			ids[0] = message.Id
			sorter = &QoSMessageSorter{
				Ids:           ids,
				Bin:           message.Bin,
				Correspondent: message.Correspondent,
				_isGroup:      message.IsGroup,
			}
			temp[mapKey] = sorter
		}
	}

	if len(temp) == 0 {
		return
	}

	// Write the QoS ack stanza...
	w := NewNodeWriter()
	w.StartTag("iq")
	w.Attribute("type", "set")
	w.Attribute("id", crypto.GenerateUUID())
	w.Attribute("cts", crypto.GetServerTimeAsString())
	w.StartTag("query")
	w.Attribute("xmlns", "kik:iq:QoS")
	w.StartTag("msg-acks")

	for _, sorter := range temp {
		w.StartTag("sender")
		w.Attribute("jid", sorter.Correspondent)
		if sorter.IsActuallyAGroup() {
			w.Attribute("g", sorter.Bin)
		}
		for _, id := range sorter.Ids {
			w.StartTag("ack-id")
			w.Attribute("receipt", "false")
			w.Text(id)
			w.EndTag("ack-id")
		}
		w.EndTag("sender")
	}

	w.EndTag("msg-acks")
	w.StartTag("history")
	w.Attribute("attach", "false")
	w.EndTag("history")
	w.EndTag("query")
	w.EndTag("iq")

	stanza := w.String()

	kikConn.Write([]byte(stanza))
}

func CreateRateLimiter() *KikRateLimiter {
	return &KikRateLimiter{
		ChatIds: *expirable.NewLRU[string, *rate.Limiter](0, nil, LRU_EXPIRE_TIME),
	}
}
