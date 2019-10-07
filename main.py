import nmap
import threading
import Queue
from flata import Flata, where, Query
from flata.storages import JSONStorage
from packaging.version import Version, parse
import pandas as pd
from flask import Flask, render_template, request, json

db1 = Flata('vuln3.json', storage=JSONStorage)
db1.table('table')
tb1 = db1.get('table')

def do_scan(targets,port,out_queue):
    result = []
    l1 = []
    nm = nmap.PortScanner()
    nm.scan(targets, port)
    host = nm.all_hosts()
    if (host !=[]):
        host = host[0]
        try:
            l1 = nm[host]['tcp'].items()
            if (l1 !=[]):
                for parsed in l1 :
                    print()
                    result.append([parsed[1]['name'], parsed[0], parsed[1]['state'], parsed[1]['product'], parsed[1]['version']])
        except:
            pass
    return out_queue.put(result)




def second_scan(nmap_report):
    result = []
    data = []
    for i in range(0, len(nmap_report)):
        host = nmap_report[i]
        version = host[4]
        protocol = str(host[1])+"/"+host[0]
        service = host[3]
        state = host[2]
        if (service != ''):
            serv2 = service
            if service.find(' ') != -1:
                    serv2 = service[:service.find(' ')]
            if version.find(' ') != -1:
                    version = version[:version.find(' ')]
            if (version !=''):
                service = host[3] + '(version= ' + version + ')'
                serv2 = serv2.lower()
                result.append([serv2, version])
        data.append([protocol, state, service])
    df1 = pd.DataFrame(data, columns=['protocol', 'state', 'service'])
    return [result, df1]

def search(name, vers):
    q = Query()
    version = parse(vers)
    vul = tb1.search((q.name == name))
    aux = False
    vulnera = {}
    if (vul != []):
        for vuln in vul:
            for ver in vuln['version']:
                if ('*' not in ver):
                    if ('<=' in ver):
                        if (version <= parse(ver[2:].strip())):
                            aux = True
                            vulnera = vuln
                            break
                    elif ('=' in ver):
                        if (version == parse(ver[1:].strip())):
                            aux = True
                            vulnera = vuln
                            break
    if aux:
        cve = vulnera['cve']
        desc = vulnera['desc']
        score = vulnera['baseScore']
        baseSeverity = vulnera['baseSeverity']
        return [name, vers, desc, score, baseSeverity, cve]
    else:
        return []


def multi_scan(target):
    thread = []
    port = ['1-100', '100-200', '200-300', '300-400', '400-500', '500-600', '600-700', '700-800', '800-900', '900-1000',
            '1001-1100', '1100-1200', '1200-1300', '1300-1400', '1400-1500', '1500-1600', '1600-1700', '1700-1800',
            '1800-1900', '1900-2000', '2001-2100', '2100-2200', '2200-2300', '2300-2400', '2400-2500', '2500-2600',
            '2600-2700', '2700-2800', '2800-2900', '2900-3000', '3001-3100', '3100-3200', '3200-3300', '3300-3400',
            '3400-3500', '3500-3600', '3600-3700', '3700-3800', '3800-3900', '3900-4000', '4001-4100', '4100-4200',
            '4200-4300', '4300-4400', '4400-4500', '4500-4600', '4600-4700', '4700-4800', '4800-4900', '4900-5000', ]
    serv = []
    res = []
    for r in range(0, 50):
        res.append(Queue.Queue())

    for t in range(0, 50):
        t1 = threading.Thread(target=do_scan, args=(target, port[t], res[t]))
        thread.append(t1)

    for j in range(0, 50):
        thread[j].start()

    for k in range(0, 50):
        thread[k].join()

    for i in range(0, 50):
        serv.append(res[i].get())

    result = []
    for list in serv:
        for service in list:
            result.append(service)

    return result

def final_test(target):
    result = []
    print ('start scan')
    report = multi_scan(target)
    print ('start search')
    list_serv = second_scan(report)
    print("les vuln sont :")
    if (list_serv != []):
        list1 = list_serv[0]
        print('les ser',list1)
        for i in range(0, len(list_serv[0])):
            res_saerch = search(list1[i][0], list1[i][1])
            if (res_saerch != []):
                result.append(res_saerch)
                print(res_saerch)
        df2 = pd.DataFrame(result, columns=['name', 'version', 'desc', 'score', 'severity', 'cve'])
    print("fin program")
    return [df2, list_serv[1]]


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('test.html')

@app.route('/test')
def test():
    return render_template('test.html')

@app.route('/filter', methods=['GET','POST'])
def filter():
    global word
    global  rep2
    word = request.form["search_word"]
    word = str(word)
    if (word !=''):
        report = final_test(word)
        out_df = report[1]
        rep2 = report[0]
        out_df = out_df.to_dict(orient='records')
        response = json.dumps(out_df, indent=2)
        return response


@app.route('/page')
def page():
    return render_template('page.html')


@app.route('/afficher', methods=['GET', 'POST'])
def afficher():
    print('err')
    df = rep2
    df = df.to_dict(orient='records')
    responses = json.dumps(df, indent=2)
    print(responses)
    return responses



if __name__ == "__main__":
    app.run(host='localhost')


