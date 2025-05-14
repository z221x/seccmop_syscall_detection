import argparse
import os
import shutil
import zipfile
import lief
import sys
class LIEFInject:
    targetso =""
    soname = ""
    apk = ""
    output = ""
    arch = "" 
    keystore = ""
    alias = ""
    password = ""
    def __init__(self,args):
        has_lib = False
        self.apk=args.apk
        self.output=args.output
        self.targetso=args.targetso
        self.soname=args.soname
        self.arch=args.arch
        if args.sign:
            self.keystore = args.keystore
            self.alias = args.alias
            self.password = args.password
        # Check if the target so file exists in the APK
        with zipfile.ZipFile(args.apk, 'r') as apk_file:
            for item in apk_file.infolist():
                if item.filename.find(args.targetso) != -1:
                    has_lib = True
                    break

        if not has_lib:
            print('apk can\'t find '+args.targetso)
            exit(1)   
    def injectso(self):
        injectso=""
        with zipfile.ZipFile(self.apk,'r')as apk_file:
            ## Extract the target so file from the APK
            for item in apk_file.infolist():
                #print(item.filename)
                if self.arch == "x86":
                    if item.filename.find("x86") != -1 and item.filename.find(self.targetso) != -1:
                        apk_file.extract(item.filename)
                        injectso=item.filename
                        break
                if self.arch == "x86_64":
                    if item.filename.find("x86_64") != -1 and item.filename.find(self.targetso) != -1:
                        apk_file.extract(item.filename)
                        injectso=item.filename
                        break
                if self.arch == "arm64":
                    if item.filename.find("arm64-v8a") != -1 and item.filename.find(self.targetso) != -1:
                        apk_file.extract(item.filename)
                        injectso=item.filename
                        break
                if self.arch == "arm":
                    if item.filename.find("armeabi-v7a") != -1 and item.filename.find(self.targetso) != -1:
                        apk_file.extract(item.filename)
                        injectso=item.filename
                        break
        #Inject the target so file into the extracted so file
        #print(injectso)
        if injectso != "":
            #print(injectso)
            so = lief.parse(injectso)
            so.add_library(self.soname)
            so.write(injectso)
        print("Inject so file success")
    def modifyapk(self):
        # Create the output directory if it doesn't exist
        (path, filename) = os.path.split(self.apk)
        (file, ext) = os.path.splitext(filename)
        outapk = os.path.join(self.output,file+"_inject.apk")
        with zipfile.ZipFile(self.apk, 'r')as orig_file:
            with zipfile.ZipFile(outapk, 'w')as out_file:
                for item in orig_file.infolist():
                    if  item.filename.find(self.targetso) != -1 and os.path.exists(os.getcwd()+"/"+item.filename):
                        out_file.write(item.filename,arcname=item.filename)
                        if self.arch == "x86":
                            out_file.write(os.path.join(os.getcwd(),self.soname),
                                           arcname="lib/x86/"+self.soname)
                        if self.arch == "x86_64":                           
                            out_file.write(os.path.join(os.getcwd(),self.soname),
                                           arcname="lib/x86_64/"+self.soname)
                        if self.arch == "arm64":
                            #print(os.path.join(os.getcwd(),self.soname))
                            out_file.write(os.path.join(os.getcwd(),self.soname),
                                           arcname="lib/arm64-v8a/"+self.soname)
                        if self.arch == "arm":
                            out_file.write(os.path.join(os.getcwd(),self.soname),
                                           arcname="lib/armeabi-v7a/"+self.soname)
                        continue
                    if item.filename.find("META-INF") == -1:
                        out_file.writestr(item, orig_file.read(item.filename))

        shutil.rmtree("lib")
        print("Modify apk success")
        return outapk
    def apksign(self, apk):
        os.system("apksigner sign --ks "+self.keystore+" --ks-key-alias "+self.alias+" --ks-pass pass:"+self.password+" --key-pass pass:"+self.password+" "+apk)
        print("Sign apk success")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('apk', help="apk path")
    parser.add_argument('output', help="Folder to store output files")
    parser.add_argument('targetso', help="Injected target so file")
    parser.add_argument('soname', help="Inject soname")
    parser.add_argument('arch', help="arch x86/x86_64/arm64/arm")
    parser.add_argument('-sign', help="Enable sign apk", action='store_true')
    parser.add_argument('--keystore', help="Path to the keystore file", default=None)
    parser.add_argument('--alias', help="Alias for the keystore", default=None)
    parser.add_argument('--password', help="Password for the keystore", default=None)
    args = parser.parse_args()
    if args.sign:
        if args.keystore is None or args.alias is None or args.password is None:
            print("Please provide keystore, alias and password for signing the APK")
            exit(1)
    liefs = LIEFInject(args)
    # inject so
    liefs.injectso()
    # modify apk
    outapk = liefs.modifyapk()
    # sign apk
    if args.sign:
        liefs.apksign(outapk)
    print("Inject success")