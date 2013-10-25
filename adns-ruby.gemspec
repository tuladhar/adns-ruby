# Ruby interface to GNU adns asynchronous-capable DNS client library.
Gem::Specification.new {|s|
	s.name = 'adns-ruby'
	s.version = '0.3'
	s.date = '2013-10-25'
	s.authors << 'Purushottam Tuladhar'
	s.email = 'purshottam.tuladhar@gmail.com'
	s.description = "Ruby interface to GNU adns asynchronous-capable DNS client library (http://gnu.org/software/adns/). You must have the GNU adns library installed in order to build this module."
	s.summary = "Ruby bindings to GNU adns library."
	s.files = ['lib/adns.rb', 'ext/adns/mod_adns.c', 'examples/a.rb', 'examples/mx.rb', 'examples/ns.rb',
		   'examples/cname.rb', 'examples/ptr.rb', 'examples/soa.rb', 'examples/txt.rb', 'examples/srv.rb',
		   'COPYING', 'README', 'CHANGELOG']
	s.extensions = ['ext/adns/extconf.rb']
	s.license = 'GNU General Public License'
	s.homepage = 'https://github.com/tuladhar/adns-ruby'
}
