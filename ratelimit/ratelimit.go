package ratelimit

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bluemods/kik-go-proxy/crypto"
	"github.com/bluemods/kik-go-proxy/node"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
)

const (
	// Max size that a batch of acks can be
	maxQosBatchSize = 50
)

var (
	// Allow 10 messages in 10s
	rateLimit      = rate.Every(10 * time.Second)
	rateLimitBurst = 10

	// Auto remove key from map after 15s
	lruExpireTime = time.Second * 15
)

// Simple rate limiter that blocks stanzas when sent too quickly.
// The server will drop spam before it reaches the client, and ack it via QoS when necessary.
// This struct makes no guarantees when it comes to thread safety.
type KikRateLimiter struct {
	// Map key is the correspondent ID ("from" attribute in message stanza)
	chatIds expirable.LRU[string, *rate.Limiter]

	// Messages currently blocked and waiting to be acked.
	blockedMessages []simpleKikMessage
}

// Bare minimum struct for a Kik message.
// Only contains the fields required for acking the stanza via QoS.
type simpleKikMessage struct {
	// The ID of the message
	Id string

	// The JID of the chat.
	// If IsGroup == true, this is the group JID.
	// Otherwise it is the same value as the Correspondent.
	Bin string

	// The JID of the sender (the user that generated the message)
	Correspondent string

	// True if this message originated from a Kik Group
	IsGroup bool
}

type qosMessageSorter struct {
	Ids           []string
	Bin           string
	Correspondent string
	isGroup       bool
}

func (q *qosMessageSorter) IsActuallyAGroup() bool {
	return q.isGroup && q.Bin != q.Correspondent && strings.HasSuffix(q.Bin, "_g@groups.kik.com")
}

// Map key used for sorting the messages for the QoS stanza.
func (m *simpleKikMessage) GetMapKey() string {
	return m.Bin + m.Correspondent + strconv.FormatBool(m.IsGroup)
}

func (i *KikRateLimiter) ProcessMessage(kikConn net.Conn, message node.Node) bool {
	if message.Name != "message" {
		return false
	}
	correspondent, exists := message.Attributes["from"]
	if !exists {
		return false
	}

	limiter, exists := i.chatIds.Get(correspondent)
	if !exists {
		limiter = rate.NewLimiter(rateLimit, rateLimitBurst)
		i.chatIds.Add(correspondent, limiter)
	}
	blocked := !limiter.Allow()
	if blocked {
		// Rate limit hit.
		// Check for 'qos' flag in message to determine if ack is needed

		qos := false
		for _, kik := range message.FindAll("kik") {
			if kik.Get("qos") != "false" {
				qos = true
				break
			}
		}

		if qos {
			id := message.Get("id")
			bin := correspondent
			g := message.FindLast("g")
			isGroup := false
			if g != nil && g.HasAttribute("jid") {
				bin = g.Get("jid")
				isGroup = true
			}

			i.blockedMessages = append(i.blockedMessages, simpleKikMessage{
				Id:            id,
				Bin:           bin,
				Correspondent: correspondent,
				IsGroup:       isGroup,
			})

			if len(i.blockedMessages) >= maxQosBatchSize {
				i.FlushMessages(kikConn)
				clear(i.blockedMessages)
			}
		}
	}
	return blocked
}

func (i *KikRateLimiter) FlushMessages(kikConn net.Conn) {
	if len(i.blockedMessages) == 0 {
		return
	}

	temp := make(map[string]*qosMessageSorter)

	for _, message := range i.blockedMessages {
		mapKey := message.GetMapKey()
		sorter, found := temp[mapKey]
		if found {
			sorter.Ids = append(sorter.Ids, message.Id)
		} else {
			ids := make([]string, 1)
			ids[0] = message.Id
			sorter = &qosMessageSorter{
				Ids:           ids,
				Bin:           message.Bin,
				Correspondent: message.Correspondent,
				isGroup:       message.IsGroup,
			}
			temp[mapKey] = sorter
		}
	}

	// Write the QoS ack stanza...
	w := node.NewNodeWriter()
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
	w.EndAllFlush()

	stanza := w.String()

	kikConn.Write([]byte(stanza))
}

func NewRateLimiter() *KikRateLimiter {
	return &KikRateLimiter{
		chatIds: *expirable.NewLRU[string, *rate.Limiter](0, nil, lruExpireTime),
	}
}
