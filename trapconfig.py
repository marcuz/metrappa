'''
Created on Nov 14, 2011
Last modified Nov 14, 2011

@author: marco
'''

import sys
import ConfigParser as configparser

class TrapConfig:

    # config file structure
    struct = {'general': {'nsca_command': True, 'strip_domains': False},
              'logging': {'debug': True, 'log': True, 'logfile': False},
              'traps': {},
              'ignore': {'traps': [], 'bgp_ip': []}}
    # these options must be boolean
    boolean = [('logging', 'debug'), ('logging', 'log')]

    def __init__(self, configfile):
        self.conf = configparser.ConfigParser()
        # case sensitive reading
        self.conf.optionxform = str
        try:
            self.conf.readfp(open(configfile))
        except IOError:
            sys.exit()

    def get_conf(self):
        if self.__check_struct() and self.__check_dep():
            return self.struct
        return None

    def __check_struct(self):
        for section in self.struct.keys():
            for option in self.struct[section].keys():
                try:
                    self.struct[section][option] = self.conf.get(section, option)
                    for b in self.boolean:
                        if b[0] == section and b[1] == option: 
                            self.struct[section][option] = self.conf.getboolean(section, option)
                except configparser.NoOptionError:
                    if self.struct[section][option]:
                        print("'[%s]->%s' missing, exiting." % (section, option))
                        return False
        return self.__load_general('traps')

    def __check_dep(self):
        # logfile: != False if log = True
        if self.struct['logging']['log'] and not self.struct['logging']['logfile']:
            return False
        return True

    def __load_general(self, section):
        try:
            options = self.conf.options(section)
            if not options:
                print("No trap details to catch in '[%s]', exiting." % section)
                return False
            for option in options:
                self.struct[section][option] = self.conf.get(section, option)
            return True
        except configparser.Error:
            print("Missing '[%s]' section, exiting." % section)
            return False

# EOF
