import os

common_libs = Split('event mhash')
lib_src = Split("""
	evws.c
	utils.c""")
lib_target = 'libs/evws'

env = Environment(ENV = os.environ, LIBPATH = './libs/')

# configuring
conf = Configure(env)

for lib in common_libs:
	if not conf.CheckLib(lib):
		print "You need library " + lib + " to compile"
		Exit(1)

for incl in ['sys/queue.h', 'event2/event.h', 'event2/listener.h', 'event2/buffer.h', 'event2/bufferevent.h', 'string.h', 'stdlib.h']:
	if not conf.CheckHeader(incl):
		print "You need header " + incl + " to compile"
		Exit(1)

env = conf.Finish()

lib = env.StaticLibrary(target = lib_target, source = lib_src, LIBS = common_libs)

env.Install('/usr/local/lib', lib)
env.Install('/usr/local/include', 'evws.h')

env.Alias('library', [lib_src])
env.Alias('install', ['/usr/local/lib', '/usr/local/include'])
