#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""

Operations:
- Test connection
- Show overall statistics (Number of tenants)
- List tenants (with search!)
--- Show tenant details
------ Active modules for particular tenant
------ Turn off protection for tenant
--- Get report(?)
--- Get report for particular tenant(?)
- Configure:
--- DSM URL
--- provide API_KEY
--- provide price (?)
+----------------------------------------------------+
| Tenants:      |                                    |
|  Search [   ] | id:                                |
|  CompanyA   ! | Name:                              |
|  CompanyB   ! | Computers count:s                    |
| [CompanyC]  # | Provisioned modules:               |
|  CompanyD   ! | AM[x] FW[ ] ..                     |
|  CompanyE   ! | Active modules:                    |
|             ! | AM[x] FW[ ]                        |
|             ! |                                    |
|             ! |                                    |
|             ! |                                    |
|             ! |                                    |
|             ! |                                    |
|  ___________! |                                    |
|               |  [Reload]           [Turn off]     |
| [Reload]      |                                    |
|----------------------------------------------------|
| [                        ] Current status          |
|----------------------------------------------------|
| [Configure]                                [Quit]  |
+----------------------------------------------------+


"""

import sys
import traceback as tb
import time
import os

import tkinter as tk
from tkinter import filedialog
from tkinter import font
import tkinter.ttk as ttk
from tkinter import messagebox

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

import json
from json.decoder import JSONDecodeError

from base64 import b64encode, b64decode
import binascii

import urllib3
from tmds import *


password = None

SALT_LENGTH = 16
KEY_LENGTH=32

def encrypt(data):
    salt = get_random_bytes(SALT_LENGTH)
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + ciphertext

def decrypt(encrypted_data):
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    tag = encrypted_data[32:48]
    ciphertext = encrypted_data[48:]

    key = PBKDF2(password, salt, dkLen=KEY_LENGTH)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

class Config:

    file_name = 'ds_mtm.json'

    def __init__(self, address='', port='', api_key=''):
        self.address = address
        self.port = port
        self.api_key = api_key

    def host(self):
        return f"https://{self.address}:{self.port}/api"

    def console(self):
        if self.address == '':
            return 'None'
        return f"https://{self.address}:{self.port}"

    def data(self):
        encrypted = encrypt(self.api_key.encode())
        return dict(address=self.address,
                    port=self.port,
                    api_key=b64encode(encrypted).decode())

    @staticmethod
    def folder():
        return os.path.abspath(os.path.dirname(os.sys.argv[0]))

    @classmethod
    def file_path(cls):
        return os.path.join(cls.folder(), cls.file_name)

    def save(self):
        with open(self.file_path(), 'w') as fp:
            json.dump(self.data(), fp)

    def load(self):
        with open(self.file_path()) as fp:
            data = json.load(fp)
            self.address = data['address']
            self.port = data['port']
            raw_api_key = b64decode(data['api_key'])
            self.api_key = encrypted = decrypt(raw_api_key)


conf = Config()

### New DS

#HOST = 'https://10.15.184.151:4119/api'
#API_KEY = '3:/ypbw0gvwaMHxHCc2SGtbbMJuWHHuz1zmEwx9ivuOOQ='


VERSION = '1.0'
MAIN_DIALOGE_TITLE = f'Multi-Tenant Managment {VERSION}'

WINDOW_WIDTH = 800
WINDOW_HEIGHT = 600
MARGIN = 20

TENANT_LIST_WIDTH = 200

TENANT_INFO_HEIGHT = WINDOW_HEIGHT - MARGIN * 6
TENANT_INFO_WIDTH = WINDOW_WIDTH - TENANT_LIST_WIDTH - MARGIN * 6

PADX = 15
PADY = 15

VSPACE = 30
SVSPACE = 25
INDENT = 50
BOTTOM_HEIGHT = 70
HSSPACE = 28
HMSPACE = 22
HBUTTON = 40
WBUTTON = 100

#LABEL_FONT = ('Verdana')  #(None, 16, font.NORMAL)
LABEL_FONT = (None, 0, font.NORMAL)
#BOLD_LABEL_FONT = (None, 0, font.BOLD)

BUTTON_FONT = LABEL_FONT
#SMALL_FONT = (None, 10, font.NORMAL)

TENANT_LIST_FONT = LABEL_FONT
#TITLE_FONT = (None, 14, font.BOLD)
#TIP_FONT = (None, 9, font.NORMAL)
#PHASES_FONT_SIZE = 12
#STATUS_FONT = (None, 9, font.NORMAL)


class MainDialogue(tk.Tk):
    def __init__(self):
        super().__init__()
        self.stop_flag = False
        self.tenant_list = None
        #self.last_selection = None
        self.tenant_list_frame = None
        self.tenant_info_frame = None
        self.bottom_frame = None
        tk.Tk.report_callback_exception = self.show_error

        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()

        pos_x = (ws - WINDOW_WIDTH) // 2
        pos_y = (hs - WINDOW_HEIGHT) // 2

        #self.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{pos_x}+{pos_y}')
        self.resizable(
            width=False,
            height=False
        )
        #cls.root.iconbitmap('te_mac.icns')
        self.title(MAIN_DIALOGE_TITLE)
        self.protocol("WM_DELETE_WINDOW", self.quit_action)
        #cls.root.attributes("-topmost", True)

        self.decorate()
        self.title(MAIN_DIALOGE_TITLE)
        #cls.root.lift()

#    def open_in_browser(self):
#        webbrowser.open_new(conf.console())

    def load_configuration(self):
        while True:
            try:
                passwd_dlg = PasswordDialogue(self)
                passwd_dlg.wait()
                if not passwd_dlg.ok:
                    self.destroy()
                    raise RuntimeError('Cancel')
                conf.load()
                self.after(0, self.tenant_list_frame.reload_action)
                return
            except FileNotFoundError as e:
                messagebox.showerror('Configuration Error',"Missing configuration file")
                self.configure_action()
            except binascii.Error as e:
                messagebox.showerror('Configuration Error', "Error reading API Key from configuration file")
                self.configure_action()
            except JSONDecodeError as e:
                messagebox.showerror('Configuration Error', "Error reading configuration file")
                self.configure_action()
            except ValueError as e:
                messagebox.showerror('Password Error', 'Wrong Password')

    def decorate(self):

        self.dsm_addr_label = tk.Label(self,
                         text=f'Deep Security Manager: {conf.console()}',
                         font=LABEL_FONT)
        self.dsm_addr_label.grid(row=0, column=0, columnspan=2, padx=PADX, pady=PADY)

        self.tenant_list_frame = TenantsList(self)
        self.tenant_list_frame.grid(row=1, column=0, sticky=tk.W)

        self.tenant_info_frame = TenantInfo(self)
        self.tenant_info_frame.grid(row=1, column=1, padx=PADX, sticky=tk.N+tk.S+tk.E+tk.W)

        self.progress_bar_frame = ProgressBarFrame()
        self.progress_bar_frame.grid(row=2, column=0, columnspan=2, pady=PADY)

        self.bottom_frame = BottomFrame(self)
        self.bottom_frame.grid(row=3, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
        #self.reload_action()


        #label = tk.Label(self, font=LABEL_FONT)
        #label.grid(row=0, column=0, columnspan=2, padx=PADX, pady=PADY)

        self.attributes('-topmost', True)
        self.update()
        self.attributes('-topmost', False)
        self.load_configuration()

        self.dsm_addr_label.config(text=f'Deep Security Manager: {conf.console()}')

    #def progress_step(self, step):
        #self.progress_bar_frame.status

    def show_error(self, *args):
        err = tb.format_exception(*args)
        messagebox.showerror('Exception', ''.join(err))

    def quit_action(self):
        answer = messagebox.askyesno(
            title='Quit',
            message='Are you sure?'
        )
        if answer:
            self.stop_flag = True
            self.quit()

    def configure_action(self):
        configuraion = ConfigurationDialog(self)
        configuraion.wait()
        if configuraion.save:
            #self.tenant_info_frame.clear()
            self.dsm_addr_label.config(text=f'Deep Security Manager: {conf.console()}')
            self.tenant_list_frame.reload_action()


class TenantsList(tk.Frame):

    TENANT_LIST_WIDTH = 19
    TENANT_LIST_HEIGHT = 19

    tenant_list_height = 18 # TENANT_LIST_FONT[1] * 18 // 16
    tenant_list_width = 19 # TENANT_LIST_FONT[1] * 19 // 16

    def __init__(self, root):
        super().__init__(
            height=self.TENANT_LIST_HEIGHT,
            width=self.TENANT_LIST_WIDTH,
            bd=0)#,
            #relief=tk.SUNKEN,
        #)
        self.root = root
        self.tenant_list = None
        self.last_selection = None
        self.decorate()

    def decorate(self):
        label = tk.Label(self, text="Tenants List:", font=LABEL_FONT)
        label.grid(row=0, column=0, sticky="W", padx=PADX)

        frame = tk.Frame(self)
        frame.grid(row=1, column=0, padx=PADX, pady=PADY)

        self.tenant_list = tk.Listbox(frame, name='tenant_list', selectmode=tk.SINGLE,
                             width=19, height=self.tenant_list_height, font=TENANT_LIST_FONT)
        self.tenant_list.pack(side="left", fill="y")
        self.tenant_list.bind('<<ListboxSelect>>', self.onselect_tenant)

        scrollbar = tk.Scrollbar(frame, orient="vertical")
        scrollbar.config(command=self.tenant_list.yview)
        scrollbar.pack(side="right", fill="y")

        self.tenant_list.config(yscrollcommand=scrollbar.set)

        self.reload_button = tk.Button(self, text=" Reload ", command=self.reload_action, font=BUTTON_FONT)
        self.reload_button.grid(row=2, column=0, sticky="E", padx=PADX)

    def onselect_tenant(self, event):
        selected = event.widget.curselection()
        if not selected:
            return
        index = int(selected[0])
        if index == self.last_selection:
            return
        self.last_selection = index
        tenant_id, tenant_name = self.tenant_list.get(self.last_selection)
        self.root.tenant_info_frame.set(tenant_id, tenant_name)
        self.root.tenant_info_frame.decorate_tenant_info()

    def selected(self):
        return self.tenant_list.get(self.last_selection)

    def reload_action(self):
        self.reload_button.config(state="disabled")
        self.root.tenant_info_frame.clear()
        self.root.progress_bar_frame.indeterminate()
        self.tenant_list.delete(0, self.tenant_list.size())
        ds = TMDS(conf.host(), conf.api_key)
        try:
            tenants = ds.tenants()
            for n, tenant in enumerate(tenants):
                self.tenant_list.insert(tk.END, (tenant.id, tenant.name))
                self.root.progress_bar_frame.step(100 * n / len(tenants), f'Add {tenant.id}')
                self.update()
        except urllib3.exceptions.MaxRetryError as e:
            messagebox.showerror("Connection error", f"{e}")
        finally:
            self.reload_button.config(state="normal")
            self.root.progress_bar_frame.hide()


class TenantInfo(tk.Frame):
    def __init__(self, root):
        super().__init__(
            #height=TENANT_INFO_HEIGHT,
            #width=TENANT_INFO_WIDTH,
            bd=1,
            relief=tk.GROOVE,
            #relief=tk.SUNKEN,
        )
        self.root = root
        self.tenant_id = None
        self.tenant_name = None
        self.modules_dict = dict()

        self.decorate()

    def decorate(self):
        row = 0
        #label = tk.Label(self.tenant_info_frame, text=f'Id: {tenant_id}', font=LABEL_FONT)
        self.id_label = tk.Label(self, text='Tenant Info', font=LABEL_FONT, padx=PADX, pady=PADY)
        self.id_label.grid(row=row, column=0, columnspan=2, sticky='ew')
        row += 1

        self.id_label = tk.Label(self, text='Id:', font=LABEL_FONT, padx=PADX, pady=0)
        self.id_label.grid(row=row, column=0, sticky=tk.W)
        self.id_value = tk.Label(self, text='', font=LABEL_FONT)
        self.id_value.grid(row=row, column=1, sticky=tk.W)
        row += 1

        self.hostname_label = tk.Label(self, text='Name:', font=LABEL_FONT, padx=PADX)
        self.hostname_label.grid(row=row, column=0, sticky=tk.W)
        self.hostname_value = tk.Label(self, text='', font=LABEL_FONT)
        self.hostname_value.grid(row=row, column=1, sticky=tk.W)
        row += 1
        #label = tk.Label(self, text='Modules State', font=LABEL_FONT)
        #label.grid(row=row, column=0, columnspan=2, pady=PADY, sticky=tk.W)

        separator = ttk.Separator(self, orient="horizontal")
        separator.grid(row=row, column=0, columnspan=2, sticky='ew')

        # self.grid_columnconfigure(0, weight=1)

        #frame = tk.Frame(self, height=2, width=30, bd=1, relief=tk.SUNKEN)
        #frame.grid(row=row, column=0, columnspan=2, pady=PADY, sticky=tk.W)

        row += 1
        for module in all_modules:
            module_name = printable(module)
#            module_font = LABEL_FONT if modules_counts[module] == 0 else BOLD_LABEL_FONT
            label = tk.Label(self, text=f"{module_name}:", font=LABEL_FONT)
            label.grid(row=row, column=0, sticky=tk.W, padx=PADX)
            value = tk.Label(self, font=LABEL_FONT)
            value.grid(row=row, column=1, sticky=tk.W)
            self.modules_dict[module] = value
            row += 1

        separator = ttk.Separator(self, orient="horizontal")
        separator.grid(row=row, column=0, columnspan=2, sticky='ew')
        row += 1

        self.turn_off_btn = tk.Button(self,
                        text=" Turn protection off ",
                        command=self.turn_off_action,
                        font=BUTTON_FONT)
        #self.turn_off_btn.config(state='disabled')
        self.turn_off_btn.grid(row=row, column=0, padx=PADX, pady=PADY)
        self.reload_btn = tk.Button(self,
                        text=" Reload ",
                        command=self.reload_tenant_action,
                        font=BUTTON_FONT)
        #self.reload_btn.config(state='disabled')
        self.reload_btn.grid(row=row, column=1, padx=PADX, pady=PADY)
        self.disable()
        #if any([modules_counts[m] for m in all_modules]) == 0:


    def clear(self):
        self.id_value.config(text='')
        self.hostname_value.config(text='')
        #self.modules_dict = dict()
        for value in self.modules_dict.values():
            value.config(text='')

        self.turn_off_btn.config(state='disabled')
        self.reload_btn.config(state='disabled')

    def set(self, tenant_id, tenant_name):
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name

    def disable(self):
        """
        w.state(['disabled']) or w.state(['!disabled','active'])
        :return:
        """
        for widget in self.winfo_children():
            try:
                widget.config(state="disabled")
            except tk.TclError:
                widget.state(['disabled'])

    def enable(self):
        for widget in self.winfo_children():
            try:
                widget.config(state="normal")
            except tk.TclError:
                widget.state(['!disabled', 'active'])

    def decorate_tenant_info(self):
        self.disable()
        self.root.progress_bar_frame.determinate()
        for modules_counts, status in self.get_tenant_info(self.tenant_id):
            #print(modules_counts, status)
            if isinstance(modules_counts, int):
                self.root.progress_bar_frame.step(modules_counts, status)
                self.root.update()
        self.root.progress_bar_frame.hide()
        self.id_value.config(text=self.tenant_id)
        self.hostname_value.config(text=self.tenant_name)
        #self.update()
        turn_off_button_state = 'disabled'
        for module_name, value in self.modules_dict.items():
#            font = LABEL_FONT
            if modules_counts[module_name] != 0:
                turn_off_button_state = 'normal'
#                font = BOLD_LABEL_FONT
            value.config(text=modules_counts[module_name], font=LABEL_FONT)
            #print('mod counts:', modules_counts[module_name])
        self.enable()
        self.turn_off_btn.config(state=turn_off_button_state)

    def get_tenant_info(self, tenant_id):
        modules = dict()
        for module in all_modules:
            modules[module] = 0
        computers_count = 0
        #packages = {package: 0 for package in all_packages}

        ds = TMDS(conf.host(), conf.api_key)
        #print(f'about to create key for {tenant_id}')
        yield 5, 'Generate key'
        tenant_api_key_id, tenant_api_key = ds.generate_api_key(tenant_id)
        #print(f'got key: {tenant_api_key_id}, {tenant_api_key}')
        tmds_tenant = TMDS(conf.host(), tenant_api_key)
        try:
            yield 10, 'Get computers list'
            computers = tmds_tenant.computers()
            for n, computer in enumerate(computers, start=1):
                yield 10 + n * 80 // len(computers), f'Host: {computer.host_name}'
                computer_modules = computer_modules_state(computer)
                for k in computer_modules:
                    modules[k] += int(computer_modules[k])
            computers_count = len(computers)
        finally:
            yield 95, 'Delete key'
            TMDS(conf.host(), tenant_api_key).delete_api_key(tenant_api_key_id)
        yield 100, 'Done'
        #print(f'Done id={tenant_id})')
        yield modules, None

    def reload_tenant_action(self):
        self.decorate()

    def turn_off_computer(self, tmds_tenant, computer):
        computer_config = deepsecurity.Computer(
            anti_malware=deepsecurity.AntiMalwareComputerExtension(state='off'),
            web_reputation=deepsecurity.WebReputationComputerExtension(state='off'),
            firewall=deepsecurity.FirewallComputerExtension(state='off'),
            intrusion_prevention=deepsecurity.IntrusionPreventionComputerExtension(state='off'),
            integrity_monitoring=deepsecurity.IntegrityMonitoringComputerExtension(state='off'),
            log_inspection=deepsecurity.LogInspectionComputerExtension(state='off'),
            application_control=deepsecurity.ApplicationControlComputerExtension(state='off')
        )
        tmds_tenant.modify_computer(computer.id, computer_config)

    def turn_off_tenant(self, tenant_id):
        ds = TMDS(conf.host(), conf.api_key)
        #print(f'about to create key for {tenant_id}')
        yield 9, 'Generate key'
        tenant_api_key_id, tenant_api_key = ds.generate_api_key(tenant_id)
        #print(f'got key: {tenant_api_key_id}, {tenant_api_key}')
        tmds_tenant = TMDS(conf.host(), tenant_api_key)
        try:
            yield 1, 'Get computers list'
            computers = tmds_tenant.computers()
            for computer in computers:
                yield 80 // len(computers), f'Process computer: {computer.host_name}'
                self.turn_off_computer(tmds_tenant, computer)
        finally:
            yield 10, 'Delete key'
            TMDS(conf.host(), tenant_api_key).delete_api_key(tenant_api_key_id)
        #print(f'Done id={tenant_id})')

    def turn_off(self):
        tenant_id, tenant_name = self.root.tenant_list_frame.selected()
        self.clear()
        self.root.progress_bar_frame.reset()
        for step, status in self.turn_off_tenant(tenant_id):
            self.root.progress_bar_frame.step(step, status)
        self.root.progress_bar_frame.hide()

    def turn_off_action(self):
        answer = messagebox.askyesno(
            title='Turn protection off',
            message='Are you sure?'
        )
        if not answer:
            return
        self.turn_off()
        self.decorate_tenant_info()


class ProgressBarFrame(tk.Frame):
    PROGRESS_BAR_LENGTH = 400
    def __init__(self):
        super().__init__()
        self.bar = ttk.Progressbar(self,
                             orient="horizontal",
                             length=self.PROGRESS_BAR_LENGTH,
                             mode="determinate",
                             maximum=100)
        self.bar.grid(row=0, column=0)

        self.status = tk.Label(self, font=LABEL_FONT)
        self.status.grid(row=1, column=0)

    def reset(self):
        self.bar['value'] = 0
        #self.bar.state(['!disabled'])
        self.update()

    def step(self, value, status):
        self.bar['value'] = value
        self.status.config(text=status)
        self.update()

    def hide(self):
        #self.bar.state(['disabled'])
        self.bar['value'] = 0
        self.status.config(text='')

    def indeterminate(self):
        self.bar.config(mode='indeterminate')

    def determinate(self):
        self.bar.config(mode='determinate')
        self.reset()


class BottomFrame(tk.Frame):
    def __init__(self, root):
        super().__init__(
            #height=40,
            #width=150,
            bd=1,
            relief=tk.SUNKEN,
        )
        self.root = root
        btn = tk.Button(self, text=" Configure... ", command=self.root.configure_action, font=BUTTON_FONT)
        btn.grid(row=0, column=0, padx=PADX, pady=PADY, sticky='e')

        btn = tk.Button(self, text=" Quit ", command=self.root.quit_action, anchor='w', font=BUTTON_FONT)
        btn.grid(row=0, column=1, padx=PADX, pady=PADY, sticky='w')


class ConfigurationDialog:

    def __init__(self, parent):
        self.parent = parent
        self.root = tk.Toplevel()
        self.root.title('Configuration')
        self.address_entry = None
        self.port_entry = None
        self.api_key_entry = None
        self.decorate()
        self.save = False

    def decorate(self):
        """
        Deep Security Manager Configuration
        IP/hostname:  _________
        Port:   ________
        API Key:  ________
        [ Cancel ]   [ Test Connection ]   [ Save ]
        """
        #self.root.attributes('-topmost', True)
        #self.root.update()
        #self.root.attributes('-topmost', False)

        label = tk.Label(self.root, text="Deep Security Manager Configuration")
        label.grid(row=0, column=0, columnspan=5, padx=PADX)
        label = tk.Label(self.root, text="IP/Hostname:")
        label.grid(row=1, column=0, padx=PADX, pady=PADY, sticky=tk.W)
        self.address_entry = tk.Entry(self.root, width=40)
        self.address_entry.insert(0, conf.address)
        self.address_entry.grid(row=1, column=1, columnspan=4, padx=PADX, pady=PADY)
        label = tk.Label(self.root, text="Port:")
        label.grid(row=2, column=0, padx=PADX, pady=PADY, sticky=tk.W)
        self.port_entry = tk.Entry(self.root, width=40)
        self.port_entry.insert(0, conf.port)
        self.port_entry.grid(row=2, column=1, columnspan=4, padx=PADX, pady=PADY)
        label = tk.Label(self.root, text="API Key:")
        label.grid(row=3, column=0, padx=PADX, pady=PADY, sticky=tk.W)
        self.api_key_entry = tk.Entry(self.root, width=40)
        self.api_key_entry.insert(0, conf.api_key)
        self.api_key_entry.grid(row=3, column=1, columnspan=4, padx=PADX, pady=PADY)
        button = tk.Button(self.root, text=" Cancel ", command=self.cancel_action)
        button.grid(row=4, column=0, padx=PADX, pady=PADY)
        button = tk.Button(self.root, text=" Help ", command=self.help_action)
        button.grid(row=4, column=1, padx=PADX, pady=PADY)
        button = tk.Button(self.root, text=" Test Connection ", command=self.test_connection_action)
        button.grid(row=4, column=2, padx=PADX, pady=PADY)
        button = tk.Button(self.root, text=" Change Password ", command=self.change_password_action)
        button.grid(row=4, column=3, padx=PADX, pady=PADY)
        button = tk.Button(self.root, text=" Save ", command=self.save_action)
        button.grid(row=4, column=4, padx=PADX, pady=PADY)

    def cancel_action(self):
        self.root.destroy()

    def help_action(self):
        messagebox.showinfo('Help', message="""
Generate API key with minimal rights:

 Administration
   -> User Managment
       -> Roles
           -> New
               -> General
                  -> General Information
                      -> Name=Accounting
                   -> Access Type
                      -> Allow Access to web services API=Check
               -> Other Rights
                   -> Multi-Tenant Administration=Custom
                       -> Can View Tenants & Multi-Tenancy System Settings=Check
                       -> Can Manage Tenants' API Keys=Check
                   ->API Keys=Custom
                       -> Can View API Keys=Check
                       -> Can Create New API Keys=Check
 Press [ Ok ]
       -> API Keys
           -> New
               -> Name=AccountingKey
               -> Role=Accounting
        """)

    def change_password_action(self):
        passwd_dlg = PasswordDialogue(self.root)
        passwd_dlg.wait()
        if not passwd_dlg.ok:
            return
        self.save_action()

    def get_conf(self):
        return Config(
            address=self.address_entry.get(),
            port=self.port_entry.get(),
            api_key=self.api_key_entry.get()
        )

    def test_connection_action(self):
        c = self.get_conf()
        ds = TMDS(c.host(), c.api_key)
        try:
            tenants = ds.tenants()
            count = len(tenants)
            messagebox.showinfo(title='Test Connection',
                                message=f'Connection is Ok. Number of tenants: {count}')
        except ApiException as e:
            messagebox.showerror(title='Test Connection',
                                 message=f'An exception occurred when calling TenantsApi.list_tenants: {e}')
        except urllib3.exceptions.HTTPError as e:
            messagebox.showerror(title='Test Connection',
                                 message=f'HTTP Error: {e}')

    def save_action(self):
        global conf
        conf = self.get_conf()
        conf.save()
        self.root.destroy()
        self.save = True

    def wait(self):
        self.parent.wait_window(self.root)



class PasswordDialogue:

    def __init__(self, parent):
        self.parent = parent
        self.root = tk.Toplevel(master=parent)
        self.root.grab_set()
        #self.root = tk.Tk()
        self.root.title('Enter Password')
        self.password_entry = None
        self.ok = None
        self.decorate()

    def decorate(self):
        """
        Deep Security Manager Configuration
        Password:  _________
        [ Cancel ]   [ Ok ]
        """

        #label = tk.Label(self.root, text="Deep Security Manager Configuration")
        #label.grid(row=0, column=0, columnspan=4, padx=PADX)
        label = tk.Label(self.root, text="Password:")
        label.grid(row=0, column=0, padx=PADX, pady=PADY, sticky=tk.W)

        self.password_entry = tk.Entry(self.root, show='*', width=40)
        self.password_entry.grid(row=0, column=1, padx=PADX, pady=PADY)

        button = tk.Button(self.root, text=" Cancel ", command=self.cancel_action)
        self.root.bind("<Escape>", self.cancel_action)
        button.grid(row=1, column=0, padx=PADX, pady=PADY, sticky=tk.W)

        button = tk.Button(self.root, text=" Ok ", command=self.ok_action)
        self.root.bind("<Return>", self.ok_action)
        button.grid(row=1, column=1, padx=PADX, pady=PADY, sticky=tk.E)


        self.password_entry.focus_set()
        self.root.attributes('-topmost', True)
        self.root.update()
        self.root.attributes('-topmost', False)

    def cancel_action(self, event=None):
        self.ok = False
        self.root.destroy()

    def ok_action(self, event=None):
        self.ok = True
        global conf
        global password
        password = self.password_entry.get()
        self.root.destroy()

    def wait(self):
        #self.root.mainloop()
        self.parent.wait_window(self.root)
        #self.root.grab_set()



def main():
    window = MainDialogue()
    window.mainloop()


if __name__ == '__main__':
    sys.exit(main())
