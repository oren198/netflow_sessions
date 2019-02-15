import csv
import socket
import hashlib
import pandas as pd


f = open(r'netflow.csv', 'r')
r = csv.reader(f)
df = pd.DataFrame()
rows = []


def validate_proto(proto_num):
    return 'tcp' if proto_num == '6' else 'udp' if proto_num == '17' else 'na'


def validate_ip(s_ip):
    try:
        socket.inet_aton(s_ip)
        return s_ip
    except socket.error:
        return 'na'


def validate_port(s_port):
    try:
        if 0 < int(s_port) < 65000:
            return s_port
    except:
        return 'na'


def get_session_id(src_ip, src_port, dst_ip, dst_port):
    return hashlib.sha1((src_ip + src_port + dst_ip + dst_port).encode('utf8')).hexdigest()


for line in r:
    parts = line[0].split()
    if len(parts) < 6:
        print(line)
        continue
    proto = validate_proto(parts[0])
    src_ip = validate_ip(parts[1])
    src_port = validate_port(parts[2])
    dst_ip = validate_ip(parts[3])
    dst_port = validate_port(parts[4])
    ts = parts[5]
    session_id = get_session_id(src_ip, src_port, dst_ip, dst_port)
    rows.append({'ts':ts,
                 'session_id': session_id,
                 'dst_ip': dst_ip,
                 'dst_port': dst_port,
                 'src_ip': src_ip,
                 'src_port': src_port,
                 'proto': proto})


f.close()
raw_pkt_df_columns = ['ts', 'session_id', 'dst_ip', 'dst_port', 'src_ip', 'src_port', 'proto']
raw_pkt_df = pd.DataFrame(data=rows, columns=raw_pkt_df_columns)

sessions_list = []
for session, group in raw_pkt_df.groupby(by='session_id'):
    sessions_list.append({'start_ts': float(group.ts.min()),
                          'end_ts': float(group.ts.max()),
                          'session_id': session,
                          'dst_ip': group.dst_ip.iloc[0],
                          'dst_port': group.dst_port.iloc[0],
                          'src_ip': group.src_ip.iloc[0],
                          'src_port': group.src_port.iloc[0],
                          'proto': group.proto.iloc[0]})

sessions_df_columns = ['start_ts', 'end_ts','session_timespan', 'session_id', 'dst_ip', 'dst_port', 'src_ip', 'src_port', 'proto']
sessions_df = pd.DataFrame(data=sessions_list, columns=sessions_df_columns)
sessions_df['span_ts'] = sessions_df.end_ts - sessions_df.start_ts
longest_sessions = sessions_df[sessions_df.dst_port == '443'].sort_values(by='span_ts', ascending=False).span_ts.head(6)

print('There are {} sessions'.format(len(sessions_df)))
print('Lonest sessions on port 443 are {}\n'.format(longest_sessions))
print('Done')
