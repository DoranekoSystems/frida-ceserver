import frida
import threading
import time
import sys
import ceserver as ce
import json

with open("config.json") as f:
    config = json.loads(f.read())

def get_device():
    mgr = frida.get_device_manager()
    changed = threading.Event()
    def on_changed():
        changed.set()
    mgr.on('changed', on_changed)
    
    device = None
    while device is None:
        devices = [dev for dev in mgr.enumerate_devices() if dev.type =='usb']
        if len(devices) == 0:
            print ('Waiting for usb device...')
            changed.wait()
        else:
            device = devices[0]
            
    mgr.off('changed', on_changed)
    return device

def main(package):
    if config["isMobile"] == 1:
        device = get_device()
        apps = device.enumerate_applications()
        target = package
        for app in apps:
            if target == app.identifier or target == app.name:
                app_identifier = app.identifier
                app_name = app.name
                break
        if config["mode"] == 0:
            process_id = device.spawn([app_identifier])
            session = device.attach(process_id)
            device.resume(process_id)
            time.sleep(1)
        else:
            session = device.attach(app_name)
    else:
        device = frida.get_remote_device()
        processes = device.enumerate_processes()
        target = package
        for process in processes:
            if target == str(process.pid) or target == process.name:
                process_name = process.name
                process_id = process.pid
                break
        session = device.attach(process_id)

    def on_message(message, data):
        print(message)

    with open("core.js","r") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()
    api = script.exports
    api.SetConfig(config)
    if config["mode"] == 1:
        info = api.GetInfo()
        process_id = info["pid"]
    ce.ceserver(process_id,api,config,session)

if __name__ == "__main__":
    args = sys.argv
    target = config["target"]
    if target == "":
        main(args[1])
    else:
        main(target)