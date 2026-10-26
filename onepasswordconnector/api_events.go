package onepasswordconnector

import "github.com/gin-gonic/gin"

// EventsAPI is unsupported: the 1Password audit feed is out of scope.
type EventsAPI struct{ *Connector }

// GetEvents - Get /events
func (api *EventsAPI) GetEvents(c *gin.Context) { DefaultHandleFunc(c) }
