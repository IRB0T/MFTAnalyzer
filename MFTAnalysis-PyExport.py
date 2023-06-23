import pyautogui as p
import time
from datetime import datetime 
import csv
import os
import pandas as pd

print('*'*50)
print("Script Start")
print('*'*50)

current_working_directory = os.getcwd()
for i, j, k in os.walk(current_working_directory):
    for f in k:
        if 'MFTECmd.exe' in f:
            MFTECmd_Path = str(os.path.join(i,f))
        if 'extension.txt' in f:
            extension_file = str(os.path.join(i,f))
        if 'sus.txt' in f:
            suspicious_file = str(os.path.join(i,f))
        if 'Common_Path.txt' in f:
            Common_know_Path = str(os.path.join(i,f))

Kw_List_Extension = []
with open(extension_file,'r') as f1:
    for i in f1:
        i = i .strip()
        Kw_List_Extension.append(i)

Kw_List_suspicious = []
with open(suspicious_file,'r') as f1:
    for i in f1:
        i = i .strip()
        Kw_List_suspicious.append(i)

Known_Path = []
with open(Common_know_Path,'r') as f1:
    for i in f1:
        i = i .strip()
        Known_Path.append(i)

start_date = str(input('Please Enter Start Date (Fromat: MM/DD/YYYY)'))
start_date = str(datetime.strptime(start_date,"%m/%d/%Y").date().strftime('%m/%d/%Y'))
end_date = str(input('Please Enter Start Date (Fromat: MM/DD/YYYY)'))
end_date = str(datetime.strptime(end_date,"%m/%d/%Y").date().strftime('%m/%d/%Y'))

MFT_File_Path = input('Locate $MFT file: ')
print('\n\n Parsing $MFT File \n')

p.keyDown('win')
p.press("r")
p.keyUp('win')
p.typewrite('cmd')
p.press("return")
time.sleep(5)

x = p.getAllTitles()
x1 = p.getWindowsWithTitle("C:\\Windows\\system32\\cmd.exe")[0]
x1.activate()
x1.maximize()
time.sleep(5)

p.typewrite(MFTECmd_Path)
time.sleep(2)
p.typewrite(" -f ")
p.typewrite(MFT_File_Path)
time.sleep(2)
p.typewrite(" --csv ")
time.sleep(2)
p.typewrite(current_working_directory)
p.press('return')

time.sleep(140)
x1.close()

for i, j, k in os.walk(current_working_directory):
    for f in k:
        if '$MFT_Output' in f:
            MFTE_Path = str(os.path.join(i,f))        
df = pd.read_csv(MFTE_Path,dtype='unicode')
pd.set_option('display.max_columns', None)

df_suspicious = pd.DataFrame(columns=['EntryNumber','SequenceNumber','ParentEntryNumber','ParentSequenceNumber','ParentPath','FileName','Extension','FileSize','Copied','Created0x10','Created0x30'])
df_count = 1

for index, row in df.iterrows():
    for j in Kw_List_suspicious:
        if row['FileName'] == j:
            df_suspicious.loc[df_count]=[row['EntryNumber'],row['SequenceNumber'],row['ParentEntryNumber'],row['ParentSequenceNumber'],row['ParentPath'],row['FileName'],row['Extension'],row['FileSize'],row['Copied'],row['Created0x10'],row['Created0x30']]
            df_count+=1

df_suspicious.sort_values(by='Created0x10',inplace=True,ascending=[True])
fnm = current_working_directory+'\\'+'Suspicious.csv'
df_suspicious.to_csv(fnm,sep=',',encoding='utf-8')


df_entries_based_on_Extension = pd.DataFrame(columns=['EntryNumber','SequenceNumber','ParentEntryNumber','ParentSequenceNumber','ParentPath','FileName','Extension','FileSize','Copied','Created0x10','Created0x30'])
df_count_ = 1


df['Date'] = pd.to_datetime(df['Created0x10']).dt.strftime('%m/%d/%Y') 
df['Date'] =pd.to_datetime(df['Date'])
df1 = df.loc[(df['Date'] >= start_date) & (df['Date'] <= end_date)]

for index, row in df1.iterrows():
    for i in Kw_List_Extension:
        if row['Extension'] == i:
            df_entries_based_on_Extension.loc[df_count_]=[row['EntryNumber'],row['SequenceNumber'],row['ParentEntryNumber'],row['ParentSequenceNumber'],row['ParentPath'],row['FileName'],row['Extension'],row['FileSize'],row['Copied'],row['Created0x10'],row['Created0x30']]
            df_count_+=1

df_entries_based_on_Extension.sort_values(by='Created0x10',inplace=True,ascending=[True])
fnm = current_working_directory+'\\'+'BasedOnExtension.csv'
df_entries_based_on_Extension.to_csv(fnm,sep=',',encoding='utf-8')

df_entries_based_on_common_know_Path = pd.DataFrame(columns=['EntryNumber','SequenceNumber','ParentEntryNumber','ParentSequenceNumber','ParentPath','FileName','Extension','FileSize','Copied','Created0x10','Created0x30'])
df_count_ = 1

for index, row in df1.iterrows():
    for i in Known_Path:
        if i in row['ParentPath']:
            for j in Kw_List_Extension:
                if row['Extension'] == j:
                    df_entries_based_on_common_know_Path.loc[df_count_]=[row['EntryNumber'],row['SequenceNumber'],row['ParentEntryNumber'],row['ParentSequenceNumber'],row['ParentPath'],row['FileName'],row['Extension'],row['FileSize'],row['Copied'],row['Created0x10'],row['Created0x30']]
                    df_count_+=1

df_entries_based_on_common_know_Path.sort_values(by='Created0x10',inplace=True,ascending=[True])
fnm = current_working_directory+'\\'+'BasedOnCommonKnowPath.csv'
df_entries_based_on_common_know_Path.to_csv(fnm,sep=',',encoding='utf-8')

print('*'*50)
print("Script END")
print('*'*50)