package pggateway

import "github.com/c653labs/pgproto"

var authPlugins = make(map[string]authPluginInitializer)
var loggingPlugins = make(map[string]loggingPluginInitializer)

type authPluginInitializer func() (AuthenticationPlugin, error)
type loggingPluginInitializer func() (LoggingPlugin, error)

type Plugin interface{}

type AuthenticationPlugin interface {
	Plugin
	Authenticate(*Session, *pgproto.StartupMessage) error
}

type LoggingContext map[string]interface{}

type LoggingPlugin interface {
	Plugin
	LogInfo(LoggingContext, string, ...interface{})
	LogDebug(LoggingContext, string, ...interface{})
	LogError(LoggingContext, string, ...interface{})
	LogFatal(LoggingContext, string, ...interface{})
	LogWarn(LoggingContext, string, ...interface{})
}

func RegisterAuthPlugin(name string, init authPluginInitializer) {
	authPlugins[name] = init
}

func RegisterLoggingPlugin(name string, init func() (LoggingPlugin, error)) {
	loggingPlugins[name] = init
}

type loggingMessage struct {
	level   string
	context LoggingContext
	msg     string
	args    []interface{}
}

type PluginRegistry struct {
	authPlugin     AuthenticationPlugin
	loggingPlugins map[string]LoggingPlugin
	log            chan loggingMessage
}

func NewPluginRegistry() (*PluginRegistry, error) {
	r := &PluginRegistry{
		authPlugin:     nil,
		loggingPlugins: make(map[string]LoggingPlugin, 0),
		log:            make(chan loggingMessage),
	}

	// TODO: Select the right plugin, rather than just using the first
	p, err := authPlugins["passthrough"]()
	if err != nil {
		return nil, err
	}
	r.authPlugin = p

	for name, init := range loggingPlugins {
		p, err := init()
		if err != nil {
			return nil, err
		}
		r.loggingPlugins[name] = p
	}

	// Go routine to handle writing log messages
	go r.handleLogging()

	return r, nil
}

func (r *PluginRegistry) handleLogging() {
	for {
		msg := <-r.log
		for _, p := range r.loggingPlugins {
			switch msg.level {
			case "info":
				p.LogInfo(msg.context, msg.msg, msg.args...)
			case "debug":
				p.LogDebug(msg.context, msg.msg, msg.args...)
			case "warn":
				p.LogWarn(msg.context, msg.msg, msg.args...)
			case "error":
				p.LogError(msg.context, msg.msg, msg.args...)
			case "fatal":
				p.LogFatal(msg.context, msg.msg, msg.args...)
			}
		}
	}
}

func (r *PluginRegistry) Authenticate(sess *Session, startup *pgproto.StartupMessage) error {
	return r.authPlugin.Authenticate(sess, startup)
}

func (r *PluginRegistry) LogInfo(context LoggingContext, msg string, args ...interface{}) {
	r.log <- loggingMessage{
		level:   "info",
		context: context,
		msg:     msg,
		args:    args,
	}
}

func (r *PluginRegistry) LogError(context LoggingContext, msg string, args ...interface{}) {
	r.log <- loggingMessage{
		level:   "error",
		context: context,
		msg:     msg,
		args:    args,
	}
}

func (r *PluginRegistry) LogWarn(context LoggingContext, msg string, args ...interface{}) {
	r.log <- loggingMessage{
		level:   "warn",
		context: context,
		msg:     msg,
		args:    args,
	}
}

func (r *PluginRegistry) LogDebug(context LoggingContext, msg string, args ...interface{}) {
	r.log <- loggingMessage{
		level:   "debug",
		context: context,
		msg:     msg,
		args:    args,
	}
}

func (r *PluginRegistry) LogFatal(context LoggingContext, msg string, args ...interface{}) {
	r.log <- loggingMessage{
		level:   "fatal",
		context: context,
		msg:     msg,
		args:    args,
	}
}
