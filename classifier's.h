
Open In Colab
import pandas as pd 
import numpy as np
from google.colab import drive
drive.mount('/content/drive')
Go to this URL in a browser: https://accounts.google.com/o/oauth2/auth?client_id=947318989803-6bn6qk8qdgf4n4g3pfee6491hc0brc4i.apps.googleusercontent.com&redirect_uri=urn%3aietf%3awg%3aoauth%3a2.0%3aoob&scope=email%20https%3a%2f%2fwww.googleapis.com%2fauth%2fdocs.test%20https%3a%2f%2fwww.googleapis.com%2fauth%2fdrive%20https%3a%2f%2fwww.googleapis.com%2fauth%2fdrive.photos.readonly%20https%3a%2f%2fwww.googleapis.com%2fauth%2fpeopleapi.readonly&response_type=code

Enter your authorization code:
··········
Mounted at /content/drive
DrDoS_DNS_data_1_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_DNS_data_1_per.csv')
DrDoS_LDAP_data_2_0_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_LDAP_data_2_0_per.csv')
DrDoS_MSSQL_data_1_3_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_MSSQL_data_1_3_per.csv')
DrDoS_NetBIOS_data_1_3_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_NetBIOS_data_1_3_per.csv')
DrDoS_NTP_data_data_5_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_NTP_data_data_5_per.csv')
DrDoS_SNMP_data_1_3_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_SNMP_data_1_3_per.csv')
DrDoS_SSDP_data_2_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_SSDP_data_2_per.csv')
DrDoS_UDP_data_2_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/DrDoS_UDP_data_2_per.csv')
Syn_data_4_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/syn_data.csv')
UDPLag_data_2_0_per = pd.read_csv('/content/drive/My Drive/DDos_Dataset/UDPLag_data_2_0_per.csv')
/usr/local/lib/python3.6/dist-packages/IPython/core/interactiveshell.py:2718: DtypeWarning: Columns (86) have mixed types.Specify dtype option on import or set low_memory=False.
  interactivity=interactivity, compiler=compiler, result=result)
# Merge all the Dataset to make one data 
data = pd.concat([DrDoS_DNS_data_1_per, DrDoS_LDAP_data_2_0_per, DrDoS_MSSQL_data_1_3_per, DrDoS_NetBIOS_data_1_3_per, DrDoS_NTP_data_data_5_per, DrDoS_SNMP_data_1_3_per, DrDoS_SSDP_data_2_per, DrDoS_UDP_data_2_per, Syn_data_4_per, UDPLag_data_2_0_per], ignore_index = True)
data.shape
(585970, 89)
data[' Label'].value_counts()
DrDoS_SNMP       67076
UDP-lag          66072
DrDoS_UDP        62702
DrDoS_NTP        60129
DrDoS_MSSQL      58802
Syn              58347
DrDoS_LDAP       54496
DrDoS_NetBIOS    53214
DrDoS_SSDP       52216
DrDoS_DNS        50715
BENIGN            2122
WebDDoS             79
Name:  Label, dtype: int64
# Drop Unnamed:0, Unnamed:0.1 columns 
data = data.drop(['Unnamed: 0', 'Unnamed: 0.1'], axis = 1)
data.columns 
Index(['Flow ID', ' Source IP', ' Source Port', ' Destination IP',
       ' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration',
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
       'Bwd Packet Length Max', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s',
       ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
       ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
       ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
       ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags',
       ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
       ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s',
       ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
       ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
       'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
       ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
       ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio',
       ' Average Packet Size', ' Avg Fwd Segment Size',
       ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
       ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
       ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
       ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
       'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
       ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean',
       ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std',
       ' Idle Max', ' Idle Min', 'SimillarHTTP', ' Inbound', ' Label'],
      dtype='object')
data_real = data.replace(np.inf, np.nan)
data_real.isnull().sum().sum()
23612
data_df = data_real.dropna(axis=0)
data_df.isnull().sum().sum()
0
data_df
Flow ID	Source IP	Source Port	Destination IP	Destination Port	Protocol	Timestamp	Flow Duration	Total Fwd Packets	Total Backward Packets	Total Length of Fwd Packets	Total Length of Bwd Packets	Fwd Packet Length Max	Fwd Packet Length Min	Fwd Packet Length Mean	Fwd Packet Length Std	Bwd Packet Length Max	Bwd Packet Length Min	Bwd Packet Length Mean	Bwd Packet Length Std	Flow Bytes/s	Flow Packets/s	Flow IAT Mean	Flow IAT Std	Flow IAT Max	Flow IAT Min	Fwd IAT Total	Fwd IAT Mean	Fwd IAT Std	Fwd IAT Max	Fwd IAT Min	Bwd IAT Total	Bwd IAT Mean	Bwd IAT Std	Bwd IAT Max	Bwd IAT Min	Fwd PSH Flags	Bwd PSH Flags	Fwd URG Flags	Bwd URG Flags	...	Packet Length Std	Packet Length Variance	FIN Flag Count	SYN Flag Count	RST Flag Count	PSH Flag Count	ACK Flag Count	URG Flag Count	CWE Flag Count	ECE Flag Count	Down/Up Ratio	Average Packet Size	Avg Fwd Segment Size	Avg Bwd Segment Size	Fwd Header Length.1	Fwd Avg Bytes/Bulk	Fwd Avg Packets/Bulk	Fwd Avg Bulk Rate	Bwd Avg Bytes/Bulk	Bwd Avg Packets/Bulk	Bwd Avg Bulk Rate	Subflow Fwd Packets	Subflow Fwd Bytes	Subflow Bwd Packets	Subflow Bwd Bytes	Init_Win_bytes_forward	Init_Win_bytes_backward	act_data_pkt_fwd	min_seg_size_forward	Active Mean	Active Std	Active Max	Active Min	Idle Mean	Idle Std	Idle Max	Idle Min	SimillarHTTP	Inbound	Label
0	172.16.0.5-192.168.50.1-556-16923-17	172.16.0.5	556	192.168.50.1	16923	17	2018-12-01 11:13:44.496470	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2144.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1072.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	DrDoS_DNS
1	172.16.0.5-192.168.50.1-690-38772-17	172.16.0.5	690	192.168.50.1	38772	17	2018-12-01 11:12:47.056822	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	DrDoS_DNS
2	172.16.0.5-192.168.50.1-761-24941-17	172.16.0.5	761	192.168.50.1	24941	17	2018-12-01 11:12:58.063304	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	DrDoS_DNS
3	172.16.0.5-192.168.50.1-526-22632-17	172.16.0.5	526	192.168.50.1	22632	17	2018-12-01 11:10:57.969713	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	DrDoS_DNS
4	172.16.0.5-192.168.50.1-546-5185-17	172.16.0.5	546	192.168.50.1	5185	17	2018-12-01 11:11:40.592201	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2280.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1140.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	DrDoS_DNS
...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...
585965	172.16.0.5-192.168.50.1-26917-29675-6	172.16.0.5	26917	192.168.50.1	29675	6	2018-12-01 13:30:12.041041	104.0	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.846154e+04	3.466667e+01	5.831238e+01	102.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	1.0	1.0	0.0	1.0	1.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	2.0	0.0	5840.0	0.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	UDP-lag
585966	172.16.0.5-192.168.50.1-33856-60933-17	172.16.0.5	33856	192.168.50.1	60933	17	2018-12-01 13:04:55.462724	2.0	2.0	0.0	750.0	0.0	375.0	375.0	375.0	0.0	0.0	0.0	0.0	0.0	3.750000e+08	1.000000e+06	2.000000e+00	0.000000e+00	2.0	2.0	2.0	2.0	0.000000e+00	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	562.5	375.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	750.0	0.0	0.0	-1.0	-1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	UDP-lag
585967	172.16.0.5-192.168.50.1-10655-18473-6	172.16.0.5	10655	192.168.50.1	18473	6	2018-12-01 13:30:08.999264	50.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	4.000000e+04	5.000000e+01	0.000000e+00	50.0	50.0	50.0	50.0	0.000000e+00	50.0	50.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	0	1.0	UDP-lag
585968	172.16.0.5-192.168.50.1-63789-3373-6	172.16.0.5	63789	192.168.50.1	3373	6	2018-12-01 13:29:53.212560	33957023.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	1.766939e-01	6.791405e+06	9.312966e+06	17686187.0	1.0	33957023.0	6791404.6	9.312966e+06	17686187.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1.0	0.0	1.0	1.0	16978510.0	1.000806e+06	17686187.0	16270833.0	0	1.0	UDP-lag
585969	172.16.0.5-192.168.50.1-62675-62675-6	172.16.0.5	62675	192.168.50.1	62675	6	2018-12-01 13:30:06.551846	16621605.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.609760e-01	3.324321e+06	6.835984e+06	15523271.0	0.0	16621605.0	3324321.0	6.835984e+06	15523271.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1098333.0	0.0	1098333.0	1098333.0	15523271.0	0.000000e+00	15523271.0	15523271.0	0	1.0	UDP-lag
574164 rows × 87 columns

# data_df.to_csv('data_final.csv', index = False)
# from google.colab import files
# files.download('data_final.csv')
data_X = data_df.drop([' Label', 'SimillarHTTP'], axis = 1)
data_X.columns 
Index(['Flow ID', ' Source IP', ' Source Port', ' Destination IP',
       ' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration',
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
       'Bwd Packet Length Max', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s',
       ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
       ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
       ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
       ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags',
       ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
       ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s',
       ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
       ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
       'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
       ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
       ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio',
       ' Average Packet Size', ' Avg Fwd Segment Size',
       ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
       ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
       ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
       ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
       'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
       ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean',
       ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std',
       ' Idle Max', ' Idle Min', ' Inbound'],
      dtype='object')
data_X.shape 
(574164, 85)
data_y = data_df[' Label']
data_y.shape 
(574164,)
data_df.isnull().sum().sum()
0
data_y.unique()
array(['DrDoS_DNS', 'BENIGN', 'DrDoS_LDAP', 'DrDoS_MSSQL',
       'DrDoS_NetBIOS', 'DrDoS_NTP', 'DrDoS_SNMP', 'DrDoS_SSDP',
       'DrDoS_UDP', 'Syn', 'UDP-lag', 'WebDDoS'], dtype=object)
data_X 
Flow ID	Source IP	Source Port	Destination IP	Destination Port	Protocol	Timestamp	Flow Duration	Total Fwd Packets	Total Backward Packets	Total Length of Fwd Packets	Total Length of Bwd Packets	Fwd Packet Length Max	Fwd Packet Length Min	Fwd Packet Length Mean	Fwd Packet Length Std	Bwd Packet Length Max	Bwd Packet Length Min	Bwd Packet Length Mean	Bwd Packet Length Std	Flow Bytes/s	Flow Packets/s	Flow IAT Mean	Flow IAT Std	Flow IAT Max	Flow IAT Min	Fwd IAT Total	Fwd IAT Mean	Fwd IAT Std	Fwd IAT Max	Fwd IAT Min	Bwd IAT Total	Bwd IAT Mean	Bwd IAT Std	Bwd IAT Max	Bwd IAT Min	Fwd PSH Flags	Bwd PSH Flags	Fwd URG Flags	Bwd URG Flags	...	Max Packet Length	Packet Length Mean	Packet Length Std	Packet Length Variance	FIN Flag Count	SYN Flag Count	RST Flag Count	PSH Flag Count	ACK Flag Count	URG Flag Count	CWE Flag Count	ECE Flag Count	Down/Up Ratio	Average Packet Size	Avg Fwd Segment Size	Avg Bwd Segment Size	Fwd Header Length.1	Fwd Avg Bytes/Bulk	Fwd Avg Packets/Bulk	Fwd Avg Bulk Rate	Bwd Avg Bytes/Bulk	Bwd Avg Packets/Bulk	Bwd Avg Bulk Rate	Subflow Fwd Packets	Subflow Fwd Bytes	Subflow Bwd Packets	Subflow Bwd Bytes	Init_Win_bytes_forward	Init_Win_bytes_backward	act_data_pkt_fwd	min_seg_size_forward	Active Mean	Active Std	Active Max	Active Min	Idle Mean	Idle Std	Idle Max	Idle Min	Inbound
0	172.16.0.5-192.168.50.1-556-16923-17	172.16.0.5	556	192.168.50.1	16923	17	2018-12-01 11:13:44.496470	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2144.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1072.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
1	172.16.0.5-192.168.50.1-690-38772-17	172.16.0.5	690	192.168.50.1	38772	17	2018-12-01 11:12:47.056822	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
2	172.16.0.5-192.168.50.1-761-24941-17	172.16.0.5	761	192.168.50.1	24941	17	2018-12-01 11:12:58.063304	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
3	172.16.0.5-192.168.50.1-526-22632-17	172.16.0.5	526	192.168.50.1	22632	17	2018-12-01 11:10:57.969713	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
4	172.16.0.5-192.168.50.1-546-5185-17	172.16.0.5	546	192.168.50.1	5185	17	2018-12-01 11:11:40.592201	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2280.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1140.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...
585965	172.16.0.5-192.168.50.1-26917-29675-6	172.16.0.5	26917	192.168.50.1	29675	6	2018-12-01 13:30:12.041041	104.0	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.846154e+04	3.466667e+01	5.831238e+01	102.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	1.0	1.0	0.0	1.0	1.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	2.0	0.0	5840.0	0.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585966	172.16.0.5-192.168.50.1-33856-60933-17	172.16.0.5	33856	192.168.50.1	60933	17	2018-12-01 13:04:55.462724	2.0	2.0	0.0	750.0	0.0	375.0	375.0	375.0	0.0	0.0	0.0	0.0	0.0	3.750000e+08	1.000000e+06	2.000000e+00	0.000000e+00	2.0	2.0	2.0	2.0	0.000000e+00	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	375.0	375.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	562.5	375.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	750.0	0.0	0.0	-1.0	-1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585967	172.16.0.5-192.168.50.1-10655-18473-6	172.16.0.5	10655	192.168.50.1	18473	6	2018-12-01 13:30:08.999264	50.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	4.000000e+04	5.000000e+01	0.000000e+00	50.0	50.0	50.0	50.0	0.000000e+00	50.0	50.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585968	172.16.0.5-192.168.50.1-63789-3373-6	172.16.0.5	63789	192.168.50.1	3373	6	2018-12-01 13:29:53.212560	33957023.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	1.766939e-01	6.791405e+06	9.312966e+06	17686187.0	1.0	33957023.0	6791404.6	9.312966e+06	17686187.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1.0	0.0	1.0	1.0	16978510.0	1.000806e+06	17686187.0	16270833.0	1.0
585969	172.16.0.5-192.168.50.1-62675-62675-6	172.16.0.5	62675	192.168.50.1	62675	6	2018-12-01 13:30:06.551846	16621605.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.609760e-01	3.324321e+06	6.835984e+06	15523271.0	0.0	16621605.0	3324321.0	6.835984e+06	15523271.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1098333.0	0.0	1098333.0	1098333.0	15523271.0	0.000000e+00	15523271.0	15523271.0	1.0
574164 rows × 85 columns

Label Encoding for the Dataset
from sklearn.preprocessing import LabelEncoder 
le = LabelEncoder()
data_y_trans = le.fit_transform(data_y)
data_y_trans
array([ 1,  1,  1, ..., 10, 10, 10])
le_fid = LabelEncoder()
le_fid.fit(data_X['Flow ID'])
data_X['Flow ID'] = le_fid.fit_transform(data_X['Flow ID'])
le_SIP = LabelEncoder()
le_SIP.fit(data_X[' Source IP'])
data_X[' Source IP'] = le_SIP.fit_transform(data_X[' Source IP'])
le_DIP = LabelEncoder()
le_DIP.fit(data_X[' Destination IP'])
data_X[' Destination IP'] = le_DIP.fit_transform(data_X[' Destination IP'])
le_timestamp = LabelEncoder()
le_timestamp.fit(data_X[' Timestamp'])
data_X[' Timestamp'] = le_timestamp.fit_transform(data_X[' Timestamp'])
data_X
Flow ID	Source IP	Source Port	Destination IP	Destination Port	Protocol	Timestamp	Flow Duration	Total Fwd Packets	Total Backward Packets	Total Length of Fwd Packets	Total Length of Bwd Packets	Fwd Packet Length Max	Fwd Packet Length Min	Fwd Packet Length Mean	Fwd Packet Length Std	Bwd Packet Length Max	Bwd Packet Length Min	Bwd Packet Length Mean	Bwd Packet Length Std	Flow Bytes/s	Flow Packets/s	Flow IAT Mean	Flow IAT Std	Flow IAT Max	Flow IAT Min	Fwd IAT Total	Fwd IAT Mean	Fwd IAT Std	Fwd IAT Max	Fwd IAT Min	Bwd IAT Total	Bwd IAT Mean	Bwd IAT Std	Bwd IAT Max	Bwd IAT Min	Fwd PSH Flags	Bwd PSH Flags	Fwd URG Flags	Bwd URG Flags	...	Max Packet Length	Packet Length Mean	Packet Length Std	Packet Length Variance	FIN Flag Count	SYN Flag Count	RST Flag Count	PSH Flag Count	ACK Flag Count	URG Flag Count	CWE Flag Count	ECE Flag Count	Down/Up Ratio	Average Packet Size	Avg Fwd Segment Size	Avg Bwd Segment Size	Fwd Header Length.1	Fwd Avg Bytes/Bulk	Fwd Avg Packets/Bulk	Fwd Avg Bulk Rate	Bwd Avg Bytes/Bulk	Bwd Avg Packets/Bulk	Bwd Avg Bulk Rate	Subflow Fwd Packets	Subflow Fwd Bytes	Subflow Bwd Packets	Subflow Bwd Bytes	Init_Win_bytes_forward	Init_Win_bytes_backward	act_data_pkt_fwd	min_seg_size_forward	Active Mean	Active Std	Active Max	Active Min	Idle Mean	Idle Std	Idle Max	Idle Min	Inbound
0	205418	17	556	129	16923	17	153807	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2144.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1072.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
1	356277	17	690	129	38772	17	149038	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
2	390438	17	761	129	24941	17	149918	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
3	172900	17	526	129	22632	17	139638	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	-2.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	-1.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
4	194820	17	546	129	5185	17	143350	1.0	2.0	0.0	2944.0	0.0	1472.0	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	2.944000e+09	2.000000e+06	1.000000e+00	0.000000e+00	1.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	1472.0	1472.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2208.0	1472.0	0.0	2280.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	2944.0	0.0	0.0	-1.0	-1.0	1.0	1140.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...
585965	38260	17	26917	129	29675	6	555528	104.0	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.846154e+04	3.466667e+01	5.831238e+01	102.0	1.0	1.0	1.0	0.000000e+00	1.0	1.0	1.0	1.0	0.0	1.0	1.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	2.0	0.0	5840.0	0.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585966	54237	17	33856	129	60933	17	514638	2.0	2.0	0.0	750.0	0.0	375.0	375.0	375.0	0.0	0.0	0.0	0.0	0.0	3.750000e+08	1.000000e+06	2.000000e+00	0.000000e+00	2.0	2.0	2.0	2.0	0.000000e+00	2.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	375.0	375.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	562.5	375.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	750.0	0.0	0.0	-1.0	-1.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585967	11899	17	10655	129	18473	6	552548	50.0	2.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	4.000000e+04	5.000000e+01	0.000000e+00	50.0	50.0	50.0	50.0	0.000000e+00	50.0	50.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	40.0	0.0	0.0	0.0	0.0	0.0	0.0	2.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	0.0	0.0	1.0
585968	309616	17	63789	129	3373	6	534101	33957023.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	1.766939e-01	6.791405e+06	9.312966e+06	17686187.0	1.0	33957023.0	6791404.6	9.312966e+06	17686187.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1.0	0.0	1.0	1.0	16978510.0	1.000806e+06	17686187.0	16270833.0	1.0
585969	292092	17	62675	129	62675	6	549955	16621605.0	6.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.000000e+00	3.609760e-01	3.324321e+06	6.835984e+06	15523271.0	0.0	16621605.0	3324321.0	6.835984e+06	15523271.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	...	0.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	1.0	0.0	0.0	0.0	0.0	0.0	0.0	0.0	120.0	0.0	0.0	0.0	0.0	0.0	0.0	6.0	0.0	0.0	0.0	5840.0	-1.0	0.0	20.0	1098333.0	0.0	1098333.0	1098333.0	15523271.0	0.000000e+00	15523271.0	15523271.0	1.0
574164 rows × 85 columns

data_X.dtypes
Flow ID                int64
 Source IP             int64
 Source Port           int64
 Destination IP        int64
 Destination Port      int64
                      ...   
Idle Mean            float64
 Idle Std            float64
 Idle Max            float64
 Idle Min            float64
 Inbound             float64
Length: 85, dtype: object
Feature Selection
from sklearn.feature_selection import chi2 
from sklearn.feature_selection import SelectKBest 
from sklearn.ensemble import ExtraTreesClassifier

#selecting 20 best features
# select_best= SelectKBest(chi2, k=20)
# X_feat_20 = select_best.fit_transform(data_X, data_y_trans)
# X_feat_20.shape

model = ExtraTreesClassifier(random_state=42)
model.fit(data_X, data_y_trans)
ExtraTreesClassifier(bootstrap=False, ccp_alpha=0.0, class_weight=None,
                     criterion='gini', max_depth=None, max_features='auto',
                     max_leaf_nodes=None, max_samples=None,
                     min_impurity_decrease=0.0, min_impurity_split=None,
                     min_samples_leaf=1, min_samples_split=2,
                     min_weight_fraction_leaf=0.0, n_estimators=100,
                     n_jobs=None, oob_score=False, random_state=42, verbose=0,
                     warm_start=False)
model.feature_importances_
array([4.55691632e-02, 1.05536287e-03, 6.07409979e-02, 4.58689181e-03,
       1.09243515e-02, 2.69234462e-02, 3.18773279e-01, 2.12886562e-03,
       4.94245245e-03, 1.89339061e-04, 1.55905431e-02, 4.16611954e-05,
       3.93580036e-02, 5.01477293e-02, 3.56746039e-02, 3.33406045e-03,
       4.44009140e-04, 2.17114614e-03, 3.51474416e-04, 3.05095572e-05,
       3.08077317e-02, 1.57018741e-02, 3.50672156e-03, 1.95113249e-03,
       3.01241816e-03, 2.95024968e-03, 2.74855882e-03, 3.00954810e-03,
       2.14181795e-03, 3.36396944e-03, 3.01320312e-03, 1.65141303e-04,
       2.48395815e-04, 1.40391633e-04, 1.60190778e-04, 2.66552490e-04,
       8.40458843e-05, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
       6.10587679e-03, 1.65195799e-04, 1.71172483e-02, 3.66112904e-04,
       5.07671691e-02, 2.94632407e-02, 4.08119261e-02, 1.57542792e-03,
       1.11100325e-03, 0.00000000e+00, 1.15744663e-05, 5.27714114e-05,
       0.00000000e+00, 3.69356260e-02, 5.04022416e-04, 1.73879536e-04,
       0.00000000e+00, 2.00405466e-03, 3.87984079e-02, 3.58090171e-02,
       9.00962226e-05, 6.01877346e-03, 0.00000000e+00, 0.00000000e+00,
       0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
       5.30061319e-03, 1.10650481e-02, 1.04462235e-04, 2.31396614e-04,
       2.15309518e-03, 9.29948216e-05, 7.84427567e-03, 6.75823061e-03,
       2.79152528e-06, 1.29557293e-06, 7.22728427e-06, 4.38285607e-06,
       2.72179345e-04, 4.54329549e-05, 3.91616930e-04, 4.85452936e-04,
       1.10824731e-03])
feature_importance_std = pd.Series(model.feature_importances_, index=data_X.columns)
feature_importance_std.nlargest(20).plot(kind='bar', title='Standardised Dataset Feature Selection using ExtraTreesClassifier')
<matplotlib.axes._subplots.AxesSubplot at 0x7f7b25845ac8>

data_X.shape 
(574164, 85)
data_new_20features_X = data_X[[' Timestamp', ' Source Port', ' Min Packet Length', ' Fwd Packet Length Min', 'Flow ID', ' Packet Length Mean', ' Fwd Packet Length Max', ' Average Packet Size', ' ACK Flag Count', ' Avg Fwd Segment Size', ' Fwd Packet Length Mean', 'Flow Bytes/s', ' Max Packet Length', ' Protocol', 'Fwd Packets/s', ' Flow Packets/s', 'Total Length of Fwd Packets', ' Subflow Fwd Bytes', ' Destination Port', ' act_data_pkt_fwd']]
data_new_20features_X
Timestamp	Source Port	Min Packet Length	Fwd Packet Length Min	Flow ID	Packet Length Mean	Fwd Packet Length Max	Average Packet Size	ACK Flag Count	Avg Fwd Segment Size	Fwd Packet Length Mean	Flow Bytes/s	Max Packet Length	Protocol	Fwd Packets/s	Flow Packets/s	Total Length of Fwd Packets	Subflow Fwd Bytes	Destination Port	act_data_pkt_fwd
0	153807	556	1472.0	1472.0	205418	1472.0	1472.0	2208.0	0.0	1472.0	1472.0	2.944000e+09	1472.0	17	2.000000e+06	2.000000e+06	2944.0	2944.0	16923	1.0
1	149038	690	1472.0	1472.0	356277	1472.0	1472.0	2208.0	0.0	1472.0	1472.0	2.944000e+09	1472.0	17	2.000000e+06	2.000000e+06	2944.0	2944.0	38772	1.0
2	149918	761	1472.0	1472.0	390438	1472.0	1472.0	2208.0	0.0	1472.0	1472.0	2.944000e+09	1472.0	17	2.000000e+06	2.000000e+06	2944.0	2944.0	24941	1.0
3	139638	526	1472.0	1472.0	172900	1472.0	1472.0	2208.0	0.0	1472.0	1472.0	2.944000e+09	1472.0	17	2.000000e+06	2.000000e+06	2944.0	2944.0	22632	1.0
4	143350	546	1472.0	1472.0	194820	1472.0	1472.0	2208.0	0.0	1472.0	1472.0	2.944000e+09	1472.0	17	2.000000e+06	2.000000e+06	2944.0	2944.0	5185	1.0
...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...	...
585965	555528	26917	0.0	0.0	38260	0.0	0.0	0.0	1.0	0.0	0.0	0.000000e+00	0.0	6	1.923077e+04	3.846154e+04	0.0	0.0	29675	0.0
585966	514638	33856	375.0	375.0	54237	375.0	375.0	562.5	0.0	375.0	375.0	3.750000e+08	375.0	17	1.000000e+06	1.000000e+06	750.0	750.0	60933	1.0
585967	552548	10655	0.0	0.0	11899	0.0	0.0	0.0	1.0	0.0	0.0	0.000000e+00	0.0	6	4.000000e+04	4.000000e+04	0.0	0.0	18473	0.0
585968	534101	63789	0.0	0.0	309616	0.0	0.0	0.0	1.0	0.0	0.0	0.000000e+00	0.0	6	1.766939e-01	1.766939e-01	0.0	0.0	3373	0.0
585969	549955	62675	0.0	0.0	292092	0.0	0.0	0.0	1.0	0.0	0.0	0.000000e+00	0.0	6	3.609760e-01	3.609760e-01	0.0	0.0	62675	0.0
574164 rows × 20 columns

Train Test Split Normal dataset 84 Features
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(data_X, data_y_trans, test_size = 0.30, random_state = 42)
X_train.shape 
(401914, 85)
X_test.shape 
(172250, 85)
Standardization of the 84 Feature Dataset
from sklearn.preprocessing import StandardScaler 
ss = StandardScaler()
X_train_std = ss.fit_transform(X_train)
X_test_std = ss.fit_transform(X_test)
Train Test Split 20 Feature Dataset
from sklearn.model_selection import train_test_split
X_train_20, X_test_20, y_train_20, y_test_20 = train_test_split(data_new_20features_X, data_y_trans, test_size = 0.30, random_state = 42)
Standardization of the 20 Feature Dataset
from sklearn.preprocessing import StandardScaler 
ss_20 = StandardScaler()
X_train_std_20 = ss_20.fit_transform(X_train_20)
X_test_std_20 = ss_20.fit_transform(X_test_20)
X_train_std_20.shape 
(401914, 20)
y_train_20.shape
(401914,)
X_test_std_20.shape 
(172250, 20)
y_test_20.shape 
(172250,)
1. Random Forest Classification
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier()
rf.fit(X_train_std_20, y_train_20)
RandomForestClassifier(bootstrap=True, ccp_alpha=0.0, class_weight=None,
                       criterion='gini', max_depth=None, max_features='auto',
                       max_leaf_nodes=None, max_samples=None,
                       min_impurity_decrease=0.0, min_impurity_split=None,
                       min_samples_leaf=1, min_samples_split=2,
                       min_weight_fraction_leaf=0.0, n_estimators=100,
                       n_jobs=None, oob_score=False, random_state=None,
                       verbose=0, warm_start=False)
rf_y_pred = rf.predict(X_test_std_20)
rf_y_pred
array([ 4,  6,  4, ..., 10,  2, 10])
from sklearn.metrics import accuracy_score 
from sklearn.metrics import classification_report 
from sklearn.metrics import confusion_matrix 
print("Classification Report for Random Forest: \n", classification_report(le.inverse_transform(y_test_20), le.inverse_transform(rf_y_pred)))
Classification Report for Random Forest: 
                precision    recall  f1-score   support

       BENIGN       0.92      1.00      0.95       616
    DrDoS_DNS       0.98      1.00      0.99     14699
   DrDoS_LDAP       0.99      0.99      0.99     15992
  DrDoS_MSSQL       0.99      1.00      0.99     17017
    DrDoS_NTP       1.00      1.00      1.00     17886
DrDoS_NetBIOS       0.99      0.99      0.99     15529
   DrDoS_SNMP       0.99      0.99      0.99     20133
   DrDoS_SSDP       0.99      0.99      0.99     15562
    DrDoS_UDP       0.99      0.99      0.99     18565
          Syn       1.00      1.00      1.00     16340
      UDP-lag       1.00      0.99      1.00     19883
      WebDDoS       1.00      0.71      0.83        28

     accuracy                           0.99    172250
    macro avg       0.99      0.97      0.98    172250
 weighted avg       0.99      0.99      0.99    172250

rf_conf_mat = confusion_matrix(y_test_20, rf_y_pred)
print("Random Forest Confusion: \n", rf_conf_mat)
Random Forest Confusion: 
 [[  615     1     0     0     0     0     0     0     0     0     0     0]
 [    1 14658     0     0    36     4     0     0     0     0     0     0]
 [    3   206 15780     3     0     0     0     0     0     0     0     0]
 [    1     0    82 16933     1     0     0     0     0     0     0     0]
 [   27     0     0     0 17859     0     0     0     0     0     0     0]
 [    3    34     0   158     1 15331     2     0     0     0     0     0]
 [    5     2     0     0     0   184 19942     0     0     0     0     0]
 [    1     0     0     1     0     1   183 15374     2     0     0     0]
 [    3     0     0     0     0     0     0   171 18390     0     1     0]
 [    2     0     0     0     0     0     0     0     0 16338     0     0]
 [    6     0     0     0     0     0     0     0   184     0 19693     0]
 [    5     0     0     0     0     0     0     0     0     0     3    20]]
acc_score = accuracy_score(y_test_20, rf_y_pred)
print("Accuracy Score for Random_Forest: \n", acc_score*100)
Accuracy Score for Random_Forest: 
 99.23541364296081
# RoC curve Function 

def RoC_Curve(classifier, X_val, y_val, title): 
        """ RoC Curve for Classifier 
        Parameters: 
        ------------
        classifier: Machine Learning Classifier to be Evaluated
        X_val: Validation Dataset
        y_val: Label/Target of Validation Dataset

        Attributes:
        Plots the Graph    
        
        Note: Some part of this Method code is taken 
            from Sklearn Website
        """

        lw = 2
        n_classes = 12
        y_test1 = to_categorical(y_val)
        pred_RFC_proba = classifier.predict_proba(X_val)
        y_score = pred_RFC_proba

        # Compute ROC curve and ROC area for each class
        fpr = dict()
        tpr = dict()
        roc_auc = dict()
        for i in range(n_classes):
            fpr[i], tpr[i], _ = roc_curve(y_test1[:, i], y_score[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])

        # Compute micro-average ROC curve and ROC area
        fpr["micro"], tpr["micro"], _ = roc_curve(y_test1.ravel(), y_score.ravel())
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])

        # First aggregate all false positive rates
        all_fpr = np.unique(np.concatenate([fpr[i] for i in range(n_classes)]))

        # Then interpolate all ROC curves at this points
        mean_tpr = np.zeros_like(all_fpr)
        for i in range(n_classes):
            mean_tpr += interp(all_fpr, fpr[i], tpr[i])

        # Finally average it and compute AUC
        mean_tpr /= n_classes

        fpr["macro"] = all_fpr
        tpr["macro"] = mean_tpr
        roc_auc["macro"] = auc(fpr["macro"], tpr["macro"])

        # Plot all ROC curves
        plt.figure(figsize=(20,10))
        plt.plot(fpr["micro"], tpr["micro"],
                label='micro-average ROC curve (area = {0:0.2f})'
                    ''.format(roc_auc["micro"]),
                color='deeppink', linestyle=':', linewidth=4)

        plt.plot(fpr["macro"], tpr["macro"],
                label='macro-average ROC curve (area = {0:0.2f})'
                    ''.format(roc_auc["macro"]),
                color='navy', linestyle=':', linewidth=4)

        list_class = ['BENIGN', 'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_NTP', 'DrDoS_NetBIOS', 'DrDoS_SNMP', 'DrDoS_SSDP', 'DrDoS_UDP', 'Syn', 'UDP-lag', 'WebDDoS']
        for i in range(n_classes):
            plt.plot(fpr[i], tpr[i], lw=lw,
                    label='ROC curve of class {0} (area = {1:0.2f})'
                    ''.format(list_class[i], roc_auc[i]))

        plt.plot([0, 1], [0, 1], 'k--', lw=lw)
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(title) 
        plt.legend(loc="lower right")
        plt.show()
from keras.utils.np_utils import to_categorical
from sklearn.metrics import roc_curve, auc
from scipy import interp
from sklearn.metrics import roc_auc_score
import matplotlib.pyplot as plt 
title = 'Receiver operating characteristic of Random Forest'
RoC_Curve(rf, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:42: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead

2. Decision Tree
from sklearn.tree import DecisionTreeClassifier 
dt = DecisionTreeClassifier()
dt.fit(X_train_std_20, y_train_20)
DecisionTreeClassifier(ccp_alpha=0.0, class_weight=None, criterion='gini',
                       max_depth=None, max_features=None, max_leaf_nodes=None,
                       min_impurity_decrease=0.0, min_impurity_split=None,
                       min_samples_leaf=1, min_samples_split=2,
                       min_weight_fraction_leaf=0.0, presort='deprecated',
                       random_state=None, splitter='best')
dt_y_pred = dt.predict(X_test_std_20)
print("Classification Report for Decision Tree: \n", classification_report(le.inverse_transform(y_test_20), le.inverse_transform(dt_y_pred)))
Classification Report for Decision Tree: 
                precision    recall  f1-score   support

       BENIGN       0.82      1.00      0.90       616
    DrDoS_DNS       0.99      0.99      0.99     14699
   DrDoS_LDAP       0.98      0.99      0.99     15992
  DrDoS_MSSQL       0.99      0.98      0.99     17017
    DrDoS_NTP       0.99      1.00      0.99     17886
DrDoS_NetBIOS       0.99      0.99      0.99     15529
   DrDoS_SNMP       0.99      0.99      0.99     20133
   DrDoS_SSDP       0.99      0.99      0.99     15562
    DrDoS_UDP       0.99      0.99      0.99     18565
          Syn       1.00      0.99      1.00     16340
      UDP-lag       1.00      0.99      0.99     19883
      WebDDoS       0.44      0.25      0.32        28

     accuracy                           0.99    172250
    macro avg       0.93      0.93      0.93    172250
 weighted avg       0.99      0.99      0.99    172250

dt_conf_mat = confusion_matrix(y_test_20, dt_y_pred)
print("Decision Tree Confusion: \n", dt_conf_mat)
Decision Tree Confusion: 
 [[  616     0     0     0     0     0     0     0     0     0     0     0]
 [    0 14502     0     0   197     0     0     0     0     0     0     0]
 [    0   204 15788     0     0     0     0     0     0     0     0     0]
 [    0     0   268 16749     0     0     0     0     0     0     0     0]
 [   38     0     0     0 17831     0     0     0     0    17     0     0]
 [    1     0     0   159     0 15369     0     0     0     0     0     0]
 [    0     0     0     0     0   186 19947     0     0     0     0     0]
 [    0     0     0     0     0     0   181 15381     0     0     0     0]
 [    0     0     0     0     0     0     0   168 18397     0     0     0]
 [   96     0     0     0     0     0     0     0     0 16244     0     0]
 [    0     0     0     0     0     0     0     0   183     0 19691     9]
 [    0     0     0     0     0     0     0     0     0     0    21     7]]
acc_score_dt = accuracy_score(y_test_20, dt_y_pred)
print("Accuracy Score for Decision Tree: \n", acc_score_dt*100)
Accuracy Score for Decision Tree: 
 98.9968069666183
# RoC Curve 
title = 'Receiver operating characteristic of Decision Tree'
RoC_Curve(dt, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:42: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead

3. SVM
from sklearn.svm import LinearSVC
svm = LinearSVC(multi_class = 'ovr')
svm.fit(X_train_std_20, y_train_20)
/usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations.
  "the number of iterations.", ConvergenceWarning)
LinearSVC(C=1.0, class_weight=None, dual=True, fit_intercept=True,
          intercept_scaling=1, loss='squared_hinge', max_iter=1000,
          multi_class='ovr', penalty='l2', random_state=None, tol=0.0001,
          verbose=0)
y_pred_svm = svm.predict(X_test_std_20) 
svm.score(X_test_std_20, y_test_20)
0.9275820029027576
print("Classification Report for Random Forest: \n", classification_report(le.inverse_transform(y_test_20), le.inverse_transform(y_pred_svm)))
Classification Report for Random Forest: 
                precision    recall  f1-score   support

       BENIGN       0.95      0.86      0.90       616
    DrDoS_DNS       0.90      0.89      0.90     14699
   DrDoS_LDAP       0.94      0.95      0.95     15992
  DrDoS_MSSQL       0.86      0.93      0.89     17017
    DrDoS_NTP       1.00      0.96      0.98     17886
DrDoS_NetBIOS       0.87      0.99      0.93     15529
   DrDoS_SNMP       0.98      0.96      0.97     20133
   DrDoS_SSDP       0.99      0.68      0.80     15562
    DrDoS_UDP       0.80      1.00      0.89     18565
          Syn       1.00      1.00      1.00     16340
      UDP-lag       1.00      0.90      0.95     19883
      WebDDoS       0.48      0.57      0.52        28

     accuracy                           0.93    172250
    macro avg       0.90      0.89      0.89    172250
 weighted avg       0.94      0.93      0.93    172250

svm_conf_mat = confusion_matrix(y_test_20, y_pred_svm)
print("SVM Confusion Matrix: \n", svm_conf_mat)
SVM Confusion Matrix: 
 [[  530     0     0    44     6     0     0     0     0    21    13     2]
 [    0 13109   814   345    39   392     0     0     0     0     0     0]
 [    1   723 15233    19     2    12     0     2     0     0     0     0]
 [    1     0   178 15853     0   967     1    16     0     0     0     1]
 [    7   685     2    39 17136     7     0     2     0     8     0     0]
 [    0     0     2   143     0 15380     0     3     0     0     0     1]
 [    0     0     0     3     0   883 19242     1     0     0     0     4]
 [    1     0     0  2059     0    11   273 10518  2700     0     0     0]
 [    1     0     0     0     0     4    32    49 18477     0     0     2]
 [    9     0     0    17     0     0     0     0     0 16314     0     0]
 [    1     0     0     0     0     0    10     0  1897     0 17968     7]
 [    8     0     0     0     0     0     0     0     0     0     4    16]]
acc_score_svm = accuracy_score(y_test_20, y_pred_svm)
print("Accuracy Score for SVM: \n", acc_score_svm*100)
Accuracy Score for SVM: 
 92.75820029027577
# RoC Curve 
# RoC curve Function 

def RoC_Curve_SVM(classifier, X_val, y_val, title): 
        """ RoC Curve for Classifier 
        Parameters: 
        ------------
        classifier: Machine Learning Classifier to be Evaluated
        X_val: Validation Dataset
        y_val: Label/Target of Validation Dataset

        Attributes:
        Plots the Graph    
        
        Note: Some part of this Method code is taken 
            from Sklearn Website
        """

        lw = 2
        n_classes = 12
        y_test1 = to_categorical(y_val)
        pred_RFC_proba = classifier.decision_function(X_val)
        y_score = pred_RFC_proba

        # Compute ROC curve and ROC area for each class
        fpr = dict()
        tpr = dict()
        roc_auc = dict()
        for i in range(n_classes):
            fpr[i], tpr[i], _ = roc_curve(y_test1[:, i], y_score[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])

        # Compute micro-average ROC curve and ROC area
        fpr["micro"], tpr["micro"], _ = roc_curve(y_test1.ravel(), y_score.ravel())
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])

        # First aggregate all false positive rates
        all_fpr = np.unique(np.concatenate([fpr[i] for i in range(n_classes)]))

        # Then interpolate all ROC curves at this points
        mean_tpr = np.zeros_like(all_fpr)
        for i in range(n_classes):
            mean_tpr += interp(all_fpr, fpr[i], tpr[i])

        # Finally average it and compute AUC
        mean_tpr /= n_classes

        fpr["macro"] = all_fpr
        tpr["macro"] = mean_tpr
        roc_auc["macro"] = auc(fpr["macro"], tpr["macro"])

        # Plot all ROC curves
        plt.figure(figsize=(20,10))
        plt.plot(fpr["micro"], tpr["micro"],
                label='micro-average ROC curve (area = {0:0.2f})'
                    ''.format(roc_auc["micro"]),
                color='deeppink', linestyle=':', linewidth=4)

        plt.plot(fpr["macro"], tpr["macro"],
                label='macro-average ROC curve (area = {0:0.2f})'
                    ''.format(roc_auc["macro"]),
                color='navy', linestyle=':', linewidth=4)

        list_class = ['BENIGN', 'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_NTP', 'DrDoS_NetBIOS', 'DrDoS_SNMP', 'DrDoS_SSDP', 'DrDoS_UDP', 'Syn', 'UDP-lag', 'WebDDoS']
        for i in range(n_classes):
            plt.plot(fpr[i], tpr[i], lw=lw,
                    label='ROC curve of class {0} (area = {1:0.2f})'
                    ''.format(list_class[i], roc_auc[i]))

        plt.plot([0, 1], [0, 1], 'k--', lw=lw)
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(title) 
        plt.legend(loc="lower right")
        plt.show()
# RoC Curve 
title = 'Receiver operating characteristic of SVM'
RoC_Curve_SVM(svm, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:43: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead

4. Naive Bayes
# from sklearn.naive_bayes import GaussianNB 
# gnb = GaussianNB()
# gnb.fit(X_train_std_20, y_train_20)
# gnb_y_pred = gnb.predict(X_test_std_20)
# print("Classification Report for Naive Bayes: \n", classification_report(le.inverse_transform(y_test_20), le.inverse_transform(gnb_y_pred)))
# gnb_conf_mat = confusion_matrix(y_test_20, gnb_y_pred)
# print("Naive Bayes Confusion Matrix: \n", gnb_conf_mat)
# acc_score_gnb = accuracy_score(y_test_20, gnb_y_pred)
# print("Accuracy Score for Naive: \n", acc_score_gnb*100)
# # RoC Curve 
# title = 'Receiver operating characteristic of Naive Bayes'
# RoC_Curve(gnb, X_test_std_20, y_test_20, title)
5. MLP
from __future__ import print_function
import pandas as pd
import numpy as np
np.random.seed(1337)  # for reproducibility
from keras.preprocessing import sequence
from keras.utils import np_utils
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Embedding
from keras.layers import LSTM, SimpleRNN, GRU
from keras.datasets import imdb
from keras.utils.np_utils import to_categorical
from sklearn.metrics import (precision_score, recall_score,f1_score, accuracy_score,mean_squared_error,mean_absolute_error)
from sklearn import metrics
from sklearn.preprocessing import Normalizer
import h5py
from keras import callbacks
from keras.callbacks import ModelCheckpoint, EarlyStopping, ReduceLROnPlateau, CSVLogger
y_train_MLP_20 = np.array(y_train_20)
y_test_MLP_20 = np.array(y_test_20)

y_train_MLP_onehot_20 = to_categorical(y_train_MLP_20)
y_test_MLP_onehot_20 = to_categorical(y_test_MLP_20)

X_train_20_MLP = np.array(X_train_std_20)
X_test_20_MLP = np.array(X_test_std_20)
# y_train_MLP = np.array(y_train)
# y_test_MLP = np.array(y_test)

# y_train_MLP_onehot = to_categorical(y_train_MLP)
# y_test_MLP_onehot = to_categorical(y_test_MLP)

# X_train_MLP = np.array(X_train_std)
# X_test_MLP = np.array(X_test_std)
batch_size = 1000

# 1. define the network
model = Sequential()
model.add(Dense(1024,input_dim=20,activation='relu'))  
model.add(Dropout(0.01))
model.add(Dense(2024,activation='relu'))  
model.add(Dropout(0.01))
# model.add(Dense(3024,activation='relu'))  
# model.add(Dropout(0.01))
# model.add(Dense(2500,activation='relu'))  
# model.add(Dropout(0.01))
model.add(Dense(2000,activation='relu'))  
model.add(Dropout(0.01))
model.add(Dense(1000,activation='relu'))  
model.add(Dropout(0.01))
model.add(Dense(500,activation='relu'))  
model.add(Dropout(0.01))
model.add(Dense(200,activation='relu'))  
model.add(Dropout(0.01))
model.add(Dense(12))
model.add(Activation('softmax'))
monitor = EarlyStopping(monitor='val_loss', min_delta=1e-3, patience=5, verbose=1, mode='auto',
      restore_best_weights=True)
# try using different optimizers and different optimizer configs
# model.compile(loss='categorical_crossentropy',optimizer='adadelta',metrics=['accuracy'])
# model.fit(X_train_20_MLP, y_train_MLP_onehot_20, validation_data=(X_test_20_MLP, y_test_MLP_onehot_20),batch_size=batch_size, epochs=100,callbacks=[monitor])
# y_pred_MLP = model.predict_classes(X_test_20_MLP)
# y_pred_MLP
# print("Classification Report for MLP: \n", classification_report(le.inverse_transform(y_test_MLP_20), le.inverse_transform(y_pred_MLP)))
# mlp_conf_mat = confusion_matrix(y_test_20, y_pred_MLP)
# print("MLP Confusion: \n", mlp_conf_mat)
# acc_score_mlp = accuracy_score(y_test_20, y_pred_MLP)
# print("Accuracy Score for MLP: \n", acc_score_mlp*100)
# RoC Curve 
# title = 'Receiver operating characteristic of MultiLayer Perceptron'
# RoC_Curve(model, X_test_std_20, y_test_20, title)
6. LSTM
y_train_lstm_20 = np.array(y_train_20)
y_test_lstm_20 = np.array(y_test_20)

y_train_onehot_lstm = to_categorical(y_train_lstm_20)
y_test_one_hot_lstm = to_categorical(y_test_lstm_20)

X_train_lstm_20 = np.array(X_train_std_20)
X_test_lstm_20 = np.array(X_test_std_20)
X_test_std_20
array([[-1.05407664, -0.90181963, -0.30345804, ...,  3.22386189,
         0.79641513,  3.23300538],
       [ 0.24816089, -0.88751843, -0.67651841, ..., -0.3061992 ,
        -1.57219156, -0.24475475],
       [-1.23226315, -0.89522235, -0.30345804, ...,  1.0835465 ,
        -1.5264022 ,  1.10376449],
       ...,
       [ 1.64529686,  1.29307531, -1.08140384, ..., -0.34333042,
         0.80340264, -0.2802421 ],
       [-0.69570018, -0.90118119,  1.52117848, ..., -0.10465283,
         0.92409597, -0.24475475],
       [ 1.67631415, -0.2734603 , -1.08140384, ..., -0.34333042,
        -0.31645152, -0.2802421 ]])
X_train_lstm_20.shape[0] 
401914
X_train_lstm_reshape = np.reshape(X_train_std_20, (X_train_lstm_20.shape[0], 1,  X_train_lstm_20.shape[1]))
X_test_lstm_reshape = np.reshape(X_test_std_20, (X_test_lstm_20.shape[0], 1, X_test_lstm_20.shape[1]))
 batch_size = 1000

# Initialize the network
model_LSTM = Sequential()
model_LSTM.add(LSTM(8,input_dim=20, return_sequences=True)) 
model_LSTM.add(Dropout(0.1))
model_LSTM.add(LSTM(8,input_dim=20, return_sequences=False))
model_LSTM.add(Dropout(0.1))
model_LSTM.add(Dense(12))
model_LSTM.add(Activation('softmax'))
monitor = EarlyStopping(monitor='val_loss', min_delta=1e-3, patience=5, verbose=1, mode='auto',
      restore_best_weights=True)
# model_LSTM.compile(loss='categorical_crossentropy',optimizer='adam',metrics=['accuracy'])
# model_LSTM.fit(X_train_lstm_reshape, y_train_onehot_lstm, validation_data=(X_test_lstm_reshape, y_test_one_hot_lstm),batch_size=batch_size, epochs=50,callbacks=[monitor])
# y_perd_lstm = model_LSTM.predict_classes(X_test_lstm_reshape)
# print("Classification Report for LSTM: \n", classification_report(le.inverse_transform(y_test_lstm_20), le.inverse_transform(y_perd_lstm)))
# lstm_conf_mat = confusion_matrix(y_test_lstm_20, y_perd_lstm)
# print("LSTM Confusion: \n", lstm_conf_mat)
# acc_score_lstm = accuracy_score(y_test_lstm_20, y_perd_lstm)
# print("Accuracy Score for MLP: \n", acc_score_lstm*100)
# RoC Curve 
# title = 'Receiver operating characteristic of LSTM'
# RoC_Curve(model_LSTM, X_test_lstm_reshape, y_test_20, title)
7. XGBoost
from sklearn.ensemble import GradientBoostingClassifier
# fit model no training data
gradinet_boost = GradientBoostingClassifier()
gradinet_boost.fit(X_train_std_20, y_train_20)
GradientBoostingClassifier(ccp_alpha=0.0, criterion='friedman_mse', init=None,
                           learning_rate=0.1, loss='deviance', max_depth=3,
                           max_features=None, max_leaf_nodes=None,
                           min_impurity_decrease=0.0, min_impurity_split=None,
                           min_samples_leaf=1, min_samples_split=2,
                           min_weight_fraction_leaf=0.0, n_estimators=100,
                           n_iter_no_change=None, presort='deprecated',
                           random_state=None, subsample=1.0, tol=0.0001,
                           validation_fraction=0.1, verbose=0,
                           warm_start=False)
# Predict the labels 
y_pred_xgboost = gradinet_boost.predict(X_test_std_20)
y_pred_xgboost
array([ 4,  6,  4, ..., 10,  2, 10])
y_test_20
array([ 4,  6,  4, ..., 10,  2, 10])
# Accuracy Score 
print("Accuracy Score for the XGBoost Classifier is: {0:.3f}%".format(accuracy_score(y_test_20, y_pred_xgboost)* 100))
Accuracy Score for the XGBoost Classifier is: 98.592%
# Classification Report 
print("Classification Report for XGBOOST: \n", classification_report(le.inverse_transform(y_test_20), le.inverse_transform(y_pred_xgboost)))
/usr/local/lib/python3.6/dist-packages/sklearn/metrics/_classification.py:1272: UndefinedMetricWarning: Precision and F-score are ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
  _warn_prf(average, modifier, msg_start, len(result))
Classification Report for XGBOOST: 
                precision    recall  f1-score   support

       BENIGN       0.47      0.45      0.46       616
    DrDoS_DNS       0.98      0.98      0.98     14699
   DrDoS_LDAP       0.98      0.98      0.98     15992
  DrDoS_MSSQL       0.98      0.99      0.98     17017
    DrDoS_NTP       0.99      0.99      0.99     17886
DrDoS_NetBIOS       0.99      0.98      0.99     15529
   DrDoS_SNMP       0.99      0.98      0.99     20133
   DrDoS_SSDP       0.98      0.99      0.98     15562
    DrDoS_UDP       0.99      0.99      0.99     18565
          Syn       1.00      0.99      1.00     16340
      UDP-lag       1.00      0.99      0.99     19883
      WebDDoS       0.00      0.00      0.00        28

     accuracy                           0.99    172250
    macro avg       0.86      0.86      0.86    172250
 weighted avg       0.99      0.99      0.99    172250

# Confusion Matrix 
xgboost_conf_mat = confusion_matrix(y_test_20, y_pred_xgboost)
print("LSTM Confusion: \n", xgboost_conf_mat)
LSTM Confusion: 
 [[  278    30   229    63     0     9     5     0     0     0     2     0]
 [   38 14422     0    27   196     0     0    16     0     0     0     0]
 [   34   207 15709    32     0     0     0     9     1     0     0     0]
 [    0     2    83 16920     0     0     0    11     1     0     0     0]
 [   36     0     0    35 17780     0     0    18    11     6     0     0]
 [   43     0     1   183     0 15289     0    10     3     0     0     0]
 [   54     8     1    36     0   186 19826    19     1     2     0     0]
 [    4     0     0     0     0     0   177 15381     0     0     0     0]
 [    0     0     0     1     0     0     0   173 18391     0     0     0]
 [   95     0     0    15     0     0    29    14     0 16187     0     0]
 [    5     0     0    27     0     0     0    18   192     0 19641     0]
 [    4     0     0    14     0     0     0     0     7     0     3     0]]
# RoC Curve 
title = 'Receiver operating characteristic of XGBOOST'
RoC_Curve(gradinet_boost, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:42: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead

Ensemble Method of Machine Learning
from sklearn.pipeline import Pipeline 
from sklearn.ensemble import AdaBoostClassifier
from sklearn.model_selection import cross_val_score
# ADABOOST 
adaboost = AdaBoostClassifier(base_estimator= dt, n_estimators=100)
adaboost.fit(X_train_std_20, y_train_20)
AdaBoostClassifier(algorithm='SAMME.R',
                   base_estimator=DecisionTreeClassifier(ccp_alpha=0.0,
                                                         class_weight=None,
                                                         criterion='gini',
                                                         max_depth=None,
                                                         max_features=None,
                                                         max_leaf_nodes=None,
                                                         min_impurity_decrease=0.0,
                                                         min_impurity_split=None,
                                                         min_samples_leaf=1,
                                                         min_samples_split=2,
                                                         min_weight_fraction_leaf=0.0,
                                                         presort='deprecated',
                                                         random_state=None,
                                                         splitter='best'),
                   learning_rate=1.0, n_estimators=100, random_state=None)
y_pred_adaboost = adaboost.predict(X_test_std_20)
print("Accuracy Score for Adaboost: ", accuracy_score(y_test_20, y_pred_adaboost))
Accuracy Score for Adaboost:  0.9899680696661829
print("Classification Report for Adaboost: ",classification_report(le.inverse_transform(y_test_20), le.inverse_transform(y_pred_adaboost)))
Classification Report for Adaboost:                 precision    recall  f1-score   support

       BENIGN       0.82      1.00      0.90       616
    DrDoS_DNS       0.99      0.99      0.99     14699
   DrDoS_LDAP       0.98      0.99      0.99     15992
  DrDoS_MSSQL       0.99      0.98      0.99     17017
    DrDoS_NTP       0.99      1.00      0.99     17886
DrDoS_NetBIOS       0.99      0.99      0.99     15529
   DrDoS_SNMP       0.99      0.99      0.99     20133
   DrDoS_SSDP       0.99      0.99      0.99     15562
    DrDoS_UDP       0.99      0.99      0.99     18565
          Syn       1.00      0.99      1.00     16340
      UDP-lag       1.00      0.99      0.99     19883
      WebDDoS       0.44      0.25      0.32        28

     accuracy                           0.99    172250
    macro avg       0.93      0.93      0.93    172250
 weighted avg       0.99      0.99      0.99    172250

# RoC Curve 
title = 'Receiver operating characteristic of ADABOOST'
RoC_Curve(adaboost, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:42: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead

# Confusion Matrix 
adaboost_conf_mat = confusion_matrix(y_test_20, y_pred_adaboost)
print("Adaboost Confusion: \n", adaboost_conf_mat)
Adaboost Confusion: 
 [[  616     0     0     0     0     0     0     0     0     0     0     0]
 [    0 14502     0     0   197     0     0     0     0     0     0     0]
 [    0   204 15788     0     0     0     0     0     0     0     0     0]
 [    0     0   268 16749     0     0     0     0     0     0     0     0]
 [   38     0     0     0 17831     0     0     0     0    17     0     0]
 [    1     0     0   159     0 15369     0     0     0     0     0     0]
 [    0     0     0     0     0   186 19947     0     0     0     0     0]
 [    0     0     0     0     0     0   181 15381     0     0     0     0]
 [    0     0     0     0     0     0     0   168 18397     0     0     0]
 [   96     0     0     0     0     0     0     0     0 16244     0     0]
 [    0     0     0     0     0     0     0     0   183     0 19691     9]
 [    0     0     0     0     0     0     0     0     0     0    21     7]]
 
# Generating output for each of the classifier for Comparision with Ensemble learning 
clf_labels = ['Decision Tree', 'SVM']
# for clf, label in zip([dt, svm, gradinet_boost, adaboost], clf_labels): 
#   scores = cross_val_score(estimator=clf, X = X_train_std_20, y = y_train_20, cv = 20, scoring = 'accuracy')
#   print("Accuracy: %0.2f (+/- %0.2f) [%s]" %(scores.mean(), scores.std() * 2, label))
# Using Majority Voting Technique for Ensemble classification 

from sklearn.base import BaseEstimator
from sklearn.base import ClassifierMixin
from sklearn.preprocessing import LabelEncoder
from sklearn.base import clone
from sklearn.pipeline import _name_estimators
import numpy as np
import operator
class MajorityVoteClassifier(BaseEstimator,
                             ClassifierMixin):
    """ A majority vote ensemble classifier
    
    Parameters
    ----------
    classifiers : array-like, shape = [n_classifiers]
      Different classifiers for the ensemble
    
    vote : str, {'classlabel', 'probability'}
      Default: 'classlabel'
      If 'classlabel' the prediction is based on
      the argmax of class labels. Else if
      'probability', the argmax of the sum of
      probabilities is used to predict the class label
      (recommended for calibrated classifiers).
    
    weights : array-like, shape = [n_classifiers]
      Optional, default: None
      If a list of `int` or `float` values are
      provided, the classifiers are weighted by
      importance; Uses uniform weights if `weights=None`.
    
    """
    def __init__(self, classifiers,
                 vote='classlabel', weights=None):
      
        
        self.classifiers = classifiers
        self.named_classifiers = {key: value for
                                  key, value in
                                  _name_estimators(classifiers)}
        self.vote = vote
        self.weights = weights
        
    def fit(self, X, y):
        """ Fit classifiers.
        
        Parameters
        ----------
        X : {array-like, sparse matrix},
            shape = [n_examples, n_features]
            Matrix of training examples.
        
        y : array-like, shape = [n_examples]
            Vector of target class labels.
        
        Returns
        -------
        self : object
        
        """
        if self.vote not in ('probability', 'classlabel'):
            raise ValueError("vote must be 'probability'"
                             "or 'classlabel'; got (vote=%r)"
                             % self.vote)
        if self.weights and len(self.weights) != len(self.classifiers):
          raise ValueError("Number of classifiers and weights"
                             "must be equal; got %d weights,"
                             "%d classifiers"
                             % (len(self.weights),
                             len(self.classifiers)))
        # Use LabelEncoder to ensure class labels start
        # with 0, which is important for np.argmax
        # call in self.predict
        self.lablenc_ = LabelEncoder()
        self.lablenc_.fit(y)
        self.classes_ = self.lablenc_.classes_
        self.classifiers_ = []
        for clf in self.classifiers:
            fitted_clf = clone(clf).fit(X,
                               self.lablenc_.transform(y))
            self.classifiers_.append(fitted_clf)
        return self
    def predict(self, X):

        """ Predict class labels for X.
        
        Parameters
        ----------
        X : {array-like, sparse matrix},
            Shape = [n_examples, n_features]
            Matrix of training examples.
        
        Returns
        ----------
        maj_vote : array-like, shape = [n_examples]
            Predicted class labels.
        
        """
        if self.vote == 'probability':
            maj_vote = np.argmax(self.predict_proba(X), axis=1)
        else: # 'classlabel' vote
            
            # Collect results from clf.predict calls
            predictions = np.asarray([clf.predict(X)
                                      for clf in
                                      self.classifiers_]).T
            
            maj_vote = np.apply_along_axis(lambda x: np.argmax(
                                           np.bincount(x,
                                           weights=self.weights)),
                                           axis=1,
                                           arr=predictions)
        maj_vote = self.lablenc_.inverse_transform(maj_vote)
        return maj_vote
    
    def predict_proba(self, X):
        """ Predict class probabilities for X.
        
        Parameters
        ----------
        X : {array-like, sparse matrix}, 
            shape = [n_examples, n_features]
            Training vectors, where
            n_examples is the number of examples and
            n_features is the number of features.
        
        Returns
        ----------
        avg_proba : array-like,
            shape = [n_examples, n_classes]
            Weighted average probability for
            each class per example.
        
        """
        probas = np.asarray([clf.predict_proba(X)
                             for clf in self.classifiers_])
        avg_proba = np.average(probas, axis=0,
                               weights=self.weights)
        return avg_proba
    
    def get_params(self, deep=True):
        """ Get classifier parameter names for GridSearch"""
        if not deep:
            return super(MajorityVoteClassifier, 
                           self).get_params(deep=False)
        else:
            out = self.named_classifiers.copy()
            for name, step in self.named_classifiers.items():
                for key, value in step.get_params(
                        deep=True).items():
                    out['%s__%s' % (name, key)] = value
            return out
# mv_clf = MajorityVoteClassifier(classifiers = [rf, gradinet_boost, dt, adaboost], vote='classlabel')
# clf_labels += ['Majority Voting']
# all_clf = [rf, dt, mv_clf]
# for clf, label in zip(all_clf, clf_labels):
#   scores = cross_val_score(estimator=clf, X = X_train_std_20, y= y_train_20, cv = 5, scoring = 'accuracy')
#   print("Accuracy Score: %0.2f (+/- %0.2f) [%s]" %(scores.mean(), scores.std()*2, label))
Ouptut for
mv_clf = MajorityVoteClassifier(classifiers = [dt, svm, gradinet_boost, adaboost], vote='classlabel') clf_labels += ['Majority Voting'] all_clf = [dt, svm, mv_clf]

output:

Accuracy Score: 1.00 (+/- 0.00) [Decision Tree]
/usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning)

Accuracy Score: 0.93 (+/- 0.00) [SVM]
/usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning) /usr/local/lib/python3.6/dist-packages/sklearn/svm/_base.py:947: ConvergenceWarning: Liblinear failed to converge, increase the number of iterations. "the number of iterations.", ConvergenceWarning)

Accuracy Score: 1.00 (+/- 0.00) [Majority Voting]
mv_clf2 = MajorityVoteClassifier(classifiers = [rf, adaboost, dt, gradinet_boost], vote='classlabel')
# Train the classifiers 
mv_clf2.fit(X_train_std_20, y_train_20)
MajorityVoteClassifier(classifiers=[RandomForestClassifier(bootstrap=True,
                                                           ccp_alpha=0.0,
                                                           class_weight=None,
                                                           criterion='gini',
                                                           max_depth=None,
                                                           max_features='auto',
                                                           max_leaf_nodes=None,
                                                           max_samples=None,
                                                           min_impurity_decrease=0.0,
                                                           min_impurity_split=None,
                                                           min_samples_leaf=1,
                                                           min_samples_split=2,
                                                           min_weight_fraction_leaf=0.0,
                                                           n_estimators=100,
                                                           n_jobs=None,
                                                           oob_scor...
                                                               max_depth=3,
                                                               max_features=None,
                                                               max_leaf_nodes=None,
                                                               min_impurity_decrease=0.0,
                                                               min_impurity_split=None,
                                                               min_samples_leaf=1,
                                                               min_samples_split=2,
                                                               min_weight_fraction_leaf=0.0,
                                                               n_estimators=100,
                                                               n_iter_no_change=None,
                                                               presort='deprecated',
                                                               random_state=None,
                                                               subsample=1.0,
                                                               tol=0.0001,
                                                               validation_fraction=0.1,
                                                               verbose=0,
                                                               warm_start=False)],
                       vote='classlabel', weights=None)
# Predict the labels 
y_pred_mjv = mv_clf2.predict(X_test_std_20)
# Classification Accuracy for Majority Voting
print("Accuracy Score for Majority Voting : ", accuracy_score(y_test_20, y_pred_mjv))
Accuracy Score for Majority Voting :  0.9900493468795356
# Classification Report 
print("Classification Report for Adaboost: ",classification_report(le.inverse_transform(y_test_20), le.inverse_transform(y_pred_mjv)))
Classification Report for Adaboost:                 precision    recall  f1-score   support

       BENIGN       0.81      1.00      0.90       616
    DrDoS_DNS       0.99      0.99      0.99     14699
   DrDoS_LDAP       0.98      0.99      0.99     15992
  DrDoS_MSSQL       0.99      0.98      0.99     17017
    DrDoS_NTP       0.99      1.00      0.99     17886
DrDoS_NetBIOS       0.99      0.99      0.99     15529
   DrDoS_SNMP       0.99      0.99      0.99     20133
   DrDoS_SSDP       0.99      0.99      0.99     15562
    DrDoS_UDP       0.99      0.99      0.99     18565
          Syn       1.00      0.99      1.00     16340
      UDP-lag       1.00      0.99      0.99     19883
      WebDDoS       0.67      0.14      0.24        28

     accuracy                           0.99    172250
    macro avg       0.95      0.92      0.92    172250
 weighted avg       0.99      0.99      0.99    172250

# Confusion Matrix 
majorityvoting_conf_mat = confusion_matrix(y_test_20, y_pred_mjv)
print("Majority Voting Confusion: \n", majorityvoting_conf_mat)
Majority Voting Confusion: 
 [[  616     0     0     0     0     0     0     0     0     0     0     0]
 [    0 14502     0     0   197     0     0     0     0     0     0     0]
 [    0   204 15788     0     0     0     0     0     0     0     0     0]
 [    0     0   268 16749     0     0     0     0     0     0     0     0]
 [   38     0     0     0 17844     0     0     0     0     4     0     0]
 [    1     0     0   159     0 15369     0     0     0     0     0     0]
 [    0     0     0     0     0   186 19947     0     0     0     0     0]
 [    0     0     0     0     0     0   181 15381     0     0     0     0]
 [    0     0     0     0     0     0     0   168 18397     0     0     0]
 [   96     0     0     0     0     0     0     0     0 16244     0     0]
 [    3     0     0     0     0     0     0     0   183     0 19695     2]
 [    3     0     0     0     0     0     0     0     0     0    21     4]]
# RoC curve for Majority Voting 

title = 'Receiver operating characteristic of Majority Voting Classifier'
RoC_Curve(mv_clf2, X_test_std_20, y_test_20, title)
/usr/local/lib/python3.6/dist-packages/ipykernel_launcher.py:42: DeprecationWarning: scipy.interp is deprecated and will be removed in SciPy 2.0.0, use numpy.interp instead
