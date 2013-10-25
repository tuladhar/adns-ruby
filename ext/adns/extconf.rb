require 'mkmf'
abort '* GNU adns library missing.' unless have_library 'adns'
abort '* GNU adn_ header missing.' unless have_header 'adns.h'
create_makefile 'adns/adns'
