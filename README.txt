Pyx (Alpha)
===

Terminal/curses based snort console and query tool

This is a linux terminal tool for querying a snort mysql DB for events.
  query specific events with sid,cid pair (pyx -e 1,100)
  query any other event element:
      pyx -id 8.8.8.8 -ud 53     # DNS events to google NS
      pyx -x ZeroAccess          # signature text
      pyx -s sensor1a            # events from a sensor
      pyx -sd 2000-01-01 -st 12:00:00 -ed 2000-01-01 -ed 13:00:00  # events in a time window
      etc
Can also be run without arguements for a live curses event console (top-like).

root@snodb:~# pyx -h
Usage:
     -h help
     -f /etc/pyx.conf              # define conf file
     -db host:db:user:pw           # db settings
     -e 123,45678                  # event payload sid,cid
     -i 1.2.3.4                    # src||dst IP
     -is 1.2.3.4                   # src IP
     -id 1.2.3.4                   # dst IP
     -ts 123                       # src tcp port
     -td 123                       # dst tcp port
     -us 123                       # src udp port
     -ud 123                       # dst udp port
     -sd date                      # start date 2000-12-31
     -st time                      # start time 24:00:00
     -ed date                      # end date 2000-12-31
     -et time                      # end time 24:00:00
     -x string                     # signature text
     -xx int                       # signature ID (sig_sid)
     -s string                     # sensor name text:if
     -ss int                       # sensor ID
     -c string                     # class text
     -cc int                       # class ID
     # To come:
     -l int                        # limit query return
     -o sd|ds|se|es|de|ed          # order by (src->dst, etc)
