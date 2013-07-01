#!/usr/bin/python

import datetime
import sys
import socket
import re

re_ip=re.compile('^[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]$')
re_dt=re.compile('^20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]$')
re_tm=re.compile('^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$')

dt = datetime.datetime.now()
dly = 60

def err():
        print 'Usage:'
        print '     -h help'
        print '     -f /etc/pyx.conf              # define conf file'
        print '     -db host:db:user:pw           # db settings'
        print '     -e 123,45678                  # event payload sid,cid'
        print '     -i 1.2.3.4                    # src||dst IP'
        print '     -is 1.2.3.4                   # src IP'
        print '     -id 1.2.3.4                   # dst IP'
        print '     -ts 123                       # src tcp port'
        print '     -td 123                       # dst tcp port'
        print '     -us 123                       # src udp port'
        print '     -ud 123                       # dst udp port'
        print '     -sd date                      # start date 2000-12-31'
        print '     -st time                      # start time 24:00:00'
        print '     -ed date                      # end date 2000-12-31'
        print '     -et time                      # end time 24:00:00'
        print '     -x string                     # signature text'
        print '     -xx int                       # signature ID (sig_sid)'
        print '     -s string                     # sensor name text:if'
        print '     -ss int                       # sensor ID'
        print '     -c string                     # class text'
        print '     -cc int                       # class ID'
        print '     -l int                        # limit query return'
        print '     -n                            # suppress printing (pyx -e s,c) links'


def conf(f):
        try:
                cf = open(f,'r')
        except Exception:
                print 'Can\'t open or read /etc/pyx.conf'
                exit()
        for l in cf:
                if 'host=' in l:
                        l = l.split('=')
                        if len(l) == 2:
                                hn = l[1].strip('\n')
                if 'db=' in l:
                        l = l.split('=')
                        if len(l) == 2:
                                db = l[1].strip('\n')
                if 'user=' in l:
                        l = l.split('=')
                        if len(l) == 2:
                                un = l[1].strip('\n')
                if 'passwd=' in l:
                        l = l.split('=')
                        if len(l) == 2:
                                pw = l[1].strip('\n')
        try:
                hn,db,un,pw
        except Exception:
                print 'Error parsing /etc/pyx.conf'
                exit()
        return hn,db,un,pw

def dbc(h,d,u,p):
        import _mysql
        try:
                global dbs
                dbs=_mysql.connect(host=h,db=d,user=u,passwd=p)
        except Exception as e:
                print 'Can not connect to DB:'
                print e
                exit()

def decip(n):
        ipo = ''
        n = int(n)
        for div in (16777216,65536,256,1):
                ipo += str(n / div)
                if div != 1:
                        ipo += '.'
                n = n % div
        return ipo

def ipdec(n):
        return str(int(n.split('.')[0]) * 16777216 + int(n.split('.')[1]) * 65536 + int(n.split('.')[2]) * 256 + int(n.split('.')[3]))


def rslv(rip):
        try:
                answ = socket.getnameinfo((rip,80),0)[0]
        except Exception:
                answ = '(resolv-fail)'
        return answ


### No passed args = CONSOLE ###
if len(sys.argv) == 1:
        try:
                c = conf('/etc/pyx.conf')
                dbc(c[0],c[1],c[2],c[3])
        except Exception:
                print 'Need default conf for console'
                exit()

        import curses,time,signal

        # Overloading WINCH, don't hate me
        def _winch(signum, frame):
                return 0
        def _iup(signum, frame):
                screen.keypad(0)
                curses.echo()
                curses.nocbreak()
                curses.endwin()
                exit()
        signal.signal(signal.SIGINT, _iup)
        signal.signal(signal.SIGWINCH, _winch)
        sys.stdout.write("\x1b[8;54;178t")

        screen = curses.initscr()
        # Manually setting R,C - WINCH is broken
        curses.resize_term(54,178)
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        screen.nodelay(1)
        screen.keypad(1)
        while 1:
                # IP hour
                qrystr = "select iphdr.ip_src,iphdr.ip_dst from event join iphdr on (event.sid = iphdr.sid and event.cid = iphdr.cid) where timestamp >= Date_Sub(NOW(),Interval 1 hour)"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                ipdat = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                ipdat.append(line)
                                rc += 1
                        except Exception:
                                rc += 1
                # TCP hour
                qrystr = "select tcphdr.tcp_sport,tcphdr.tcp_dport from event join tcphdr on (event.sid = tcphdr.sid and event.cid = tcphdr.cid) where timestamp >= Date_Sub(NOW(),Interval 1 hour)"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                tcpdat = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                tcpdat.append(line)
                                rc += 1
                        except Exception:
                                rc += 1
                # UDP hour
                qrystr = "select udphdr.udp_sport,udphdr.udp_dport from event join udphdr on (event.sid = udphdr.sid and event.cid = udphdr.cid) where timestamp >= Date_Sub(NOW(),Interval 1 hour)"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                udpdat = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                udpdat.append(line)
                                rc += 1
                        except Exception:
                                rc += 1
                # Last 40
                qrystr = "select event.timestamp,signature.sig_name,iphdr.ip_src,iphdr.ip_dst from event left join (signature,iphdr) on (event.signature = signature.sig_id and event.sid = iphdr.sid and event.cid = iphdr.cid) where event.timestamp >= Date_Sub(NOW(), Interval 1 hour) order by event.timestamp desc limit 24"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                rcnt = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                _rcnt = line[0].split(' ')[1]+'  '+line[1]
                                _rcnt = _rcnt[:52].ljust(52)
                                _rcnt += ' '+decip(line[2]).rjust(15)
                                #_rcnt += '>'+decip(line[3])
                                rcnt.append(_rcnt)
                                rc += 1
                        except Exception:
                                rc += 1
                # Top events
                qrystr = "select distinct sig_name,count(cid) from event join signature on signature = sig_id where timestamp >= Date_Sub(NOW(),Interval 1 hour) group by signature order by count(cid) desc limit 24"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                tope = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                _tope = line[1]+' x '+line[0]
                                _tope = _tope[:52]
                                tope.append(_tope)
                                rc += 1
                        except Exception:
                                rc += 1
                # Rare Events
                qrystr = "select t.* from (select distinct sig_name, count(cid) as c from event join signature on signature = sig_id where timestamp >= Date_Sub(NOW(),Interval 1 hour) group by signature order by event.timestamp ) as t where t.c = '1' limit 24"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                rrev = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                _rrev = line[0][:52]
                                rrev.append(_rrev)
                                rc += 1
                        except Exception:
                                rc += 1

                #### Count and sort ip src/dst
                ipsrcC = dict()
                ipdstC = dict()
                ipsrcUd = dict()
                ipdstUs = dict()
                for isd in ipdat:
                        # Src x Uniq Dst
                        try:
                                ipsrcUd[isd[0]].add(isd[1])
                        except KeyError:
                                ipsrcUd[isd[0]] = set()
                                ipsrcUd[isd[0]].add(isd[1])
                        # Dst x Uniq Src
                        try:
                                ipdstUs[isd[1]].add(isd[0])
                        except KeyError:
                                ipdstUs[isd[1]] = set()
                                ipdstUs[isd[1]].add(isd[0])
                        # Src x Event
                        try:
                                ipsrcC[isd[0]] += 1
                        except KeyError:
                                ipsrcC[isd[0]] = 1
                        # Dst x Event
                        try:
                                ipdstC[isd[1]] += 1
                        except KeyError:
                                ipdstC[isd[1]] = 1

                ipsd = []
                for sud in ipsrcUd:
                        ipsd.append((len(ipsrcUd[sud]),sud))
                ipsd = sorted(ipsd,reverse=True)
                ipds = []
                for dus in ipdstUs:
                        ipds.append((len(ipdstUs[dus]),dus))
                ipds = sorted(ipds,reverse=True)
                ipsrc = []
                for isC in ipsrcC:
                        ipsrc.append((ipsrcC[isC],isC))
                ipsrc = sorted(ipsrc,reverse=True)
                ipdst = []
                for idC in ipdstC:
                        ipdst.append((ipdstC[idC],idC))
                ipdst = sorted(ipdst,reverse=True)

                #### Count and sort tcp src/dst
                tcpsrcC = dict()
                tcpdstC = dict()
                for isd in tcpdat:
                        try:
                                tcpsrcC[isd[0]] += 1
                        except KeyError:
                                tcpsrcC[isd[0]] = 1
                        try:
                                tcpdstC[isd[1]] += 1
                        except KeyError:
                                tcpdstC[isd[1]] = 1
                tcpsrc = []
                for tsC in tcpsrcC:
                        tcpsrc.append((tcpsrcC[tsC],tsC))
                tcpsrc = sorted(tcpsrc,reverse=True)
                tcpdst = []
                for tdC in tcpdstC:
                        tcpdst.append((tcpdstC[tdC],tdC))
                tcpdst = sorted(tcpdst,reverse=True)

                #### Count and sort udp src/dst
                udpsrcC = dict()
                udpdstC = dict()
                for isd in udpdat:
                        try:
                                udpsrcC[isd[0]] += 1
                        except KeyError:
                                udpsrcC[isd[0]] = 1
                        try:
                                udpdstC[isd[1]] += 1
                        except KeyError:
                                udpdstC[isd[1]] = 1
                udpsrc = []
                for usC in udpsrcC:
                        udpsrc.append((udpsrcC[usC],usC))
                udpsrc = sorted(udpsrc,reverse=True)

                udpdst = []
                for udC in udpdstC:
                        udpdst.append((udpdstC[udC],udC))
                udpdst = sorted(udpdst,reverse=True)

                ### Write Out
                screen.clear()
                screen.addstr(0,0,'Top Event Counts')
                screen.addstr(0,52,' | Recent Events')
                screen.addstr(0,123,' | Rare Events')
                x = 0
                for ln in tope:
                        x += 1
                        screen.addstr(x,0,ln)
                x = 0
                for ln in rcnt:
                        x += 1
                        screen.addstr(x,52,' | '+ln)
                x = 0
                for ln in rrev:
                        x += 1
                        screen.addstr(x,123,' | '+ln)

                # Bottom Row
                x = 26
                screen.addstr(x,0,'Top Src x Event')
                screen.addstr(x,24,' | Top Dst x Event')
                screen.addstr(x,51,' | Top Src x Dst')
                screen.addstr(x,78,' | Top Dst x Src')
                screen.addstr(x,105,' | Top TCP Src Prt')
                screen.addstr(x,123,' | Top TCP Dst Prt')
                screen.addstr(x,141,' | Top UDP Src Prt')
                screen.addstr(x,158,' | Top UDP Dst Prt')
                x = 26
                for ln in ipsrc[:26]:
                        x += 1
                        _ln = decip(ln[1]).ljust(15)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,0,_ln)
                x = 26
                for ln in ipdst[:26]:
                        x += 1
                        _ln = ' | '+decip(ln[1]).ljust(15)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,24,_ln)
                x = 26
                for ln in ipsd[:26]:
                        x += 1
                        _ln = ' | '+decip(ln[1]).ljust(15)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,51,_ln)
                x = 26
                for ln in ipds[:26]:
                        x += 1
                        _ln = ' | '+decip(ln[1]).ljust(15)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,78,_ln)
                x = 26
                for ln in tcpsrc[:26]:
                        x += 1
                        _ln = ' | '+ln[1].ljust(5)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,105,_ln)
                x = 26
                for ln in tcpdst[:26]:
                        x += 1
                        _ln = ' | '+ln[1].ljust(5)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,123,_ln)
                x = 26
                for ln in udpsrc[:26]:
                        x += 1
                        _ln = ' | '+ln[1].ljust(5)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,141,_ln)
                x = 26
                for ln in udpdst[:26]:
                        x += 1
                        _ln = ' | '+ln[1].ljust(5)+' x '+str(ln[0]).rjust(6)
                        screen.addstr(x,158,_ln)
                screen.refresh()
                # Sleep loop
                rng = range(10)
                for x in rng:
                        cdt = datetime.datetime.now()
                        cdt = cdt.strftime('%Y/%m/%d %H:%M:%S')
                        screen.addstr(53,0,cdt+' (-'+str(dly-(dly/10.0*x))+'s) (r|efresh) (q|uit)')
                        screen.refresh()
                        kp = screen.getch()
                        if kp == 113: # 'q'
                                # force quit
                                screen.keypad(0)
                                curses.echo()
                                curses.nocbreak()
                                curses.endwin()
                                exit()
                        if kp == 114: # 'r'
                                # force refresh
                                break
                        time.sleep(dly/10.0)


        # Trapping the impossibru
        screen.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
        exit()

### Got args, search or event
if len(sys.argv) > 1:
        # Parse args
        sid,cid = None,None
        ip,sip,dip = None,None,None
        stcp,dtcp,sudp,dudp = None,None,None,None
        sdt,stm = dt.strftime('%Y-%m-%d'), '00:00:00'
        edt,etm = dt.strftime('%Y-%m-%d'), '23:59:59'
        sigx,sigid = None,None
        snsrx,snsrid = None,None
        clsx,clsid = None,None
        lim,odr,nol = 1000,None,False

        sa = sys.argv
        sa.pop(0)
        while 1:
                try:
                        a = sa.pop(0)
                except Exception:
                        break

                if a == '-h':
                        err()
                        exit()

                if a == '-f':
                        try:
                                cf = sa.pop(0)
                        except Exception:
                                print '-f has no path/file.conf'
                                exit()
                        c = conf(cf)
                        hn,db,un,pw = c[0],c[1],c[2],c[3]

                if a == '-db':
                        # -db will override conf files every time
                        try:
                                cd = sa.pop(0)
                        except Exception:
                                print '-C has no host:db:user:pw'
                                exit()
                        cd = cd.split(':')
                        hn,db,un,pw = cd[0],cd[1],cd[2],cd[3]

                if a == '-e':
                        try:
                                e = sa.pop(0)
                        except Exception:
                                print '-e has no sid,cid'
                                exit()
                        sid,cid = e.split(',')[0],e.split(',')[1]
                        try:
                                int(sid)
                                int(cid)
                        except Exception:
                                print 'Malformed sid,cid'
                                exit()

                if a == '-i':
                        try:
                                ip = sa.pop(0)
                        except Exception:
                                print '-i has no IP'
                                exit()
                        if not re_ip.search(ip):
                                print 'Malformed IP'
                                exit()

                if a == '-is':
                        try:
                                sip = sa.pop(0)
                        except Exception:
                                print '-is has no src IP'
                                exit()
                        if not re_ip.search(sip):
                                print 'Malformed IP'
                                exit()

                if a == '-id':
                        try:
                                dip = sa.pop(0)
                        except Exception:
                                print '-id has no dst IP'
                                exit()
                        if not re_ip.search(dip):
                                print 'Malformed IP'
                                exit()


                if a == '-ts':
                        try:
                                stcp = sa.pop(0)
                        except Exception:
                                print '-ts has no tcp src port'
                                exit()
                        try:
                                int(stcp)
                        except Exception:
                                print 'Malformed port'
                                exit()

                if a == '-td':
                        try:
                                dtcp = sa.pop(0)
                        except Exception:
                                print '-td has no tcp dst port'
                                exit()
                        try:
                                int(dtcp)
                        except Exception:
                                print 'Malformed port'
                                exit()

                if a == '-us':
                        try:
                                sudp = sa.pop(0)
                        except Exception:
                                print '-us has no udp src port'
                                exit()
                        try:
                                int(sudp)
                        except Exception:
                                print 'Malformed port'
                                exit()

                if a == '-ud':
                        try:
                                dudp = sa.pop(0)
                        except Exception:
                                print '-ud has no udp dst port'
                                exit()
                        try:
                                int(dudp)
                        except Exception:
                                print 'Malformed port'
                                exit()

                if a == '-sd':
                        try:
                                sdt = sa.pop(0)
                        except Exception:
                                print '-sd has no start date'
                                exit()
                        if not re_dt.search(sdt):
                                print 'Malformed start date'
                                exit()

                if a == '-st':
                        try:
                                stm = sa.pop(0)
                        except Exception:
                                print '-st has no start time'
                                exit()
                        if not re_tm.search(stm):
                                print 'Malformed start time'
                                exit()

                if a == '-ed':
                        try:
                                edt = sa.pop(0)
                        except Exception:
                                print '-ed has no end date'
                                exit()
                        if not re_dt.search(edt):
                                print 'Malformed end date'
                                exit()

                if a == '-et':
                        try:
                                etm = sa.pop(0)
                        except Exception:
                                print '-et has no end time'
                                exit()
                        if not re_tm.search(etm):
                                print 'Malformed end time'
                                exit()

                if a == '-x':
                        try:
                                sigx = sa.pop(0)
                        except Exception:
                                print '-x has no signature text'
                                exit()
                        if len(sigx) <= 3:
                                print 'Signature text too small'
                                exit()

                if a == '-xx':
                        try:
                                sigid = sa.pop(0)
                        except Exception:
                                print '-X has no signature ID'
                                exit()
                        try:
                                int(sigid)
                        except Exception:
                                print 'Malformed signature ID'
                                exit()

                if a == '-s':
                        try:
                                snsrx = sa.pop(0)
                        except Exception:
                                print '-s has no sensor text'
                                exit()
                        if len(snsrx) <= 1:
                                print 'Sensor text too small'
                                exit()

                if a == '-ss':
                        try:
                                snsrid = sa.pop(0)
                        except Exception:
                                print '-S has no sensor ID'
                                exit()

                if a == '-c':
                        try:
                                clsx = sa.pop(0)
                        except Exception:
                                print '-c has no class text'
                                exit()

                if a == '-cc':
                        try:
                                clsid = sa.pop(0)
                        except Exception:
                                print '-cc has no class ID'
                                exit()

                if a == '-l':
                        try:
                                lim = sa.pop(0)
                        except Exception:
                                print '-l has no limit'
                                exit()
                        try:
                                int(lim)
                        except Exception:
                                print 'limit has to be a number'
                                exit()
                if a == '-n':
                        nol = True

        # Additional sanity
        if (stcp or dtcp) and (sudp or dudp):
                print 'Got both tcp and udp ports, pick one'
                exit()
        if sigx and sigid:
                print 'Got both sig text and id, pick one'
                exit()
        if clsx and clsid:
                print 'Got both cls text and id, pick one'
                exit()
        if snsrx and snsrid:
                print 'Got both snsr text and id, pick one'
                exit()
        if ip:
                # ip overrides sip,dip
                sip = ip
                dip = ip


        # If we got conf from file or args use them, otherwise default
        try:
                dbc(hn,db,un,pw)
        except Exception:
                c = conf('/etc/pyx.conf')
                dbc(c[0],c[1],c[2],c[3])

        # If we are calling an event, do that and exit ignoring all the other cruft.
        if sid and cid:
                from binascii import unhexlify as unhex
                qrystr = "select event.timestamp,sensor.hostname,sensor.interface,signature.sig_name,signature.sig_sid,"
                qrystr += "iphdr.ip_src,iphdr.ip_dst,iphdr.ip_ver,iphdr.ip_tos,iphdr.ip_hlen,iphdr.ip_len,"
                qrystr += "iphdr.ip_id,iphdr.ip_flags,iphdr.ip_off,iphdr.ip_ttl,iphdr.ip_proto,iphdr.ip_csum "
                qrystr += "from event left join(sensor,signature,iphdr) on (event.sid = sensor.sid and event.signature = signature.sig_id and event.sid = iphdr.sid and event.cid = iphdr.cid) where event.cid = '"+cid+"' and event.sid = '"+sid+"'"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                try:
                        eve=dbqry.fetch_row()[0]
                except Exception:
                        print 'sid,cid pair doesn\'t exist'
                        exit()

                # TCP Port?
                qrystr = "select * from tcphdr where cid = '"+cid+"' and sid = '"+sid+"'"
                dbs.query(qrystr)
                dbqry = dbs.store_result()
                try:
                        tcpsd = dbqry.fetch_row()[0]
                except Exception:
                        tcpsd = None

                # UDP Port?
                qrystr = "select * from udphdr where cid = '"+cid+"' and sid = '"+sid+"'"
                dbs.query(qrystr)
                dbqry = dbs.store_result()
                try:
                        udpsd = dbqry.fetch_row()[0]
                except Exception:
                        udpsd = None

                # ICMP Port?
                qrystr = "select * from icmphdr where cid = '"+cid+"' and sid = '"+sid+"'"
                dbs.query(qrystr)
                dbqry = dbs.store_result()
                try:
                        icmpsd = dbqry.fetch_row()[0]
                except Exception:
                        icmpsd = None

                if tcpsd:
                        sdp = 'tcp',tcpsd[2],tcpsd[3],'seq:'+tcpsd[4]+', ack:'+tcpsd[5]+', offset:'+tcpsd[6]+', flgs:'+tcpsd[8]+', win:'+tcpsd[9]+', urg:'+tcpsd[10]+', chk:'+tcpsd[11]
                elif udpsd:
                        sdp = 'udp',udpsd[2],udpsd[3],'len:'+udpsd[4]+', chk:'+udpsd[5]
                elif icmpsd:
                        sdp = 'icmp','','','type:'+icmpsd[2]+', code:'+icmpsd[3]+', chk:'+icmpsd[4]+', id:'+icmpsd[5]+', seq:'+icmpsd[6]

                qrystr = "select data_payload from data where cid = '"+cid+"' and sid = '"+sid+"'"
                dbs.query(qrystr)
                dbqry = dbs.store_result()
                try:
                        payl = dbqry.fetch_row()[0]
                except Exception:
                        payl = None
                if payl:
                        paylc = unhex(str(payl[0]))
                else:
                        paylc = "No Payload Data"
                from curses.ascii import isprint as pq
                payo = ''
                for c in paylc:
                        if pq(c):
                                payo += c
                        elif c == '\n':
                                payo += '\n'

                print '\n Time: '+eve[0]+'  Sensor: '+eve[1]+':'+eve[2]
                print ' Event: '+eve[3]+' ('+eve[4]+')'
                print ' SrcIP: '+decip(eve[5])+' '+sdp[1]+'/'+sdp[0]+' - '+rslv(decip(eve[5]))
                print ' DstIP: '+decip(eve[6])+' '+sdp[2]+'/'+sdp[0]+' - '+rslv(decip(eve[6]))
                print ' IP {ver:'+eve[7]+', tos:'+eve[8]+', hlen:'+eve[9]+',dlen:'+eve[10]+', id:'+eve[11]+', flgs:'+eve[12]+', offset:'+eve[13]+', ttl:'+eve[14]+', prt:'+eve[15]+', chk:'+eve[16]
                print ' '+sdp[0].upper()+' {'+sdp[3]+'}'
                print '--------------------------------------------------------------------------------'
                print payo
                print ''
                exit()

        # Searching for something
        elif ip or sip or dip or stcp or dtcp or sudp or dudp or sigx or sigid or clsx or clsid or snsrx or snsrid or sdt or stm or edt or etm:
                # Sid, Sensor, IF List
                qrystr = "select sid,hostname,interface from sensor order by sid"
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                sensors = {}
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                if line[0] and line[1] and line[2]:
                                        sensors[line[0]] = line[1]+':'+line[2]
                                        rc += 1
                        except Exception:
                                rc += 1
                # Pre-fetch event.sids from searched snsrx for "IN" qrystr
                ssl = []
                if snsrx:
                        for ss in sensors:
                                if snsrx in sensors[ss]:
                                        # search sid list
                                        ssl.append(ss)
                if len(ssl) == 0:
                        print 'No sensor matching '+snsrx
                        exit()
                sl = ''
                for s in ssl:
                        sl += "'"+s+"',"
                sl = sl.rstrip(',')

                qrystr =  "select event.sid, event.cid, event.timestamp, signature.sig_sid, signature.sig_name, sig_class.sig_class_name, iphdr.ip_src, iphdr.ip_dst"
                if stcp or dtcp:
                        qrystr += ",tcphdr.tcp_sport,tcphdr.tcp_dport"
                if sudp or dudp:
                        qrystr += ",udphdr.udp_sport,udphdr.udp_dport"
                qrystr += " from event left join (iphdr, signature, sig_class"
                if stcp or dtcp:
                        qrystr += ",tcphdr"
                if sudp or dudp:
                        qrystr += ",udphdr"
                qrystr += ") on (event.sid = iphdr.sid and event.cid = iphdr.cid and event.signature = signature.sig_id and "
                qrystr += "signature.sig_class_id = sig_class.sig_class_id "
                if stcp or dtcp:
                        qrystr += "and tcphdr.sid = event.sid and tcphdr.cid = event.cid "
                if sudp or dudp:
                        qrystr += "and udphdr.sid = event.sid and udphdr.cid = event.cid "
                qrystr += ") where "
                qrystr += "timestamp >= '"+sdt+" "+stm+"' and "
                qrystr += "timestamp <= '"+edt+" "+etm+"' "
                if sip and not dip:
                        qrystr += "and iphdr.ip_src = "+ipdec(sip)+" "
                if dip and not sip:
                        qrystr += "and iphdr.ip_dst = "+ipdec(dip)+" "
                if sip and dip:
                        qrystr += "and ((iphdr.ip_src = "+ipdec(sip)+") or (iphdr.ip_dst = "+ipdec(dip)+"))"
                if stcp:
                        qrystr += "and tcphdr.tcp_sport = '"+stcp+"' "
                if dtcp:
                        qrystr += "and tcphdr.tcp_dport = '"+dtcp+"' "
                if sudp:
                        qrystr += "and udphdr.udp_sport = '"+sudp+"' "
                if dudp:
                        qrystr += "and udphdr.udp_dport = '"+dudp+"' "
                if snsrx:
                        qrystr += "and event.sid in ("+sl+") "
                if snsrid:
                        qrystr += " and event.sid = '"+snsrid+"'"
                if clsx:
                        qrystr += " and sig_class.sig_class_name like '%"+clsx+"%'"
                if clsid:
                        qrystr += " and sig_class.sig_class_id = '"+clsid+"'"
                if sigx:
                        qrystr += " and signature.sig_name like '%"+sigx+"%'"
                if sigid:
                        qrystr += " and signature.sig_id = '"+sigid+"'"
                #
                dbs.query(qrystr)
                dbqry=dbs.store_result()
                store = []
                rc = 0
                while rc != dbqry.num_rows():
                        line = dbqry.fetch_row()[0]
                        try:
                                store.append(line)
                                rc += 1
                        except Exception:
                                rc += 1


                lc = 0
                try:
                        if lim:
                                limit = int(lim)
                except Exception:
                        limit = 10000

                for ln in store:
                        limit -= 1
                        if limit == 0:
                                break
                        if lc == 0:
                                print 'Sensor'.ljust(15),
                                print 'Timestamp'.ljust(20),
                                print 'SrcIP'.ljust(21),
                                print 'DstIP'.ljust(21),
                                print 'SigID'.ljust(10),
                                #print 'Class'.ljust(20),
                                if nol == True:
                                        print 'Event'
                                else:
                                        print 'Event(link)'
                        lc += 1
                        if lc == 50:
                                lc = 0
                        print sensors[ln[0]].ljust(15),
                        print ln[2].ljust(20),
                        if stcp or sudp or sudp or dudp:
                                o = decip(ln[6])+':'+ln[8]
                                print o.ljust(21),
                        else:
                                print decip(ln[6]).ljust(21),
                        if stcp or sudp or dtcp or dudp:
                                o = decip(ln[7])+':'+ln[9]
                                print o.ljust(21),
                        else:
                                print decip(ln[7]).ljust(21),
                        print ln[3].ljust(10),
                        #print ln[5].ljust(20),
                        print ln[4][:86],
                        if nol == True:
                                print ''
                        else:
                                print '( pyx -e '+ln[0]+','+ln[1]+' )'
                exit()
