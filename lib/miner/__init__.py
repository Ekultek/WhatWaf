import os
import stat
import json
import shlex
import shutil
import random
import platform
import threading
import subprocess

try:
    import psutil
    IS_INSTALLED = True
except ImportError:
    IS_INSTALLED = False

import lib.settings
import lib.formatter
import lib.firewall_found


try:
    input = raw_input
except NameError:
    pass


class Miner(object):

    def __init__(self, opted):
        self.miner_home = lib.settings.OPTIONAL_MINING_FOLDER_PATH
        self.miner_conf_path = lib.settings.OPTIONAL_MINING_CONFIG_PATH
        self.miner_path = lib.settings.OPTIONAL_MINING_MINERS
        self.wallets = lib.settings.OPTIONAL_MINING_WHATWAF_WALLETS
        self.pools = lib.settings.OPTIONS_MINING_POOLS
        self.do_opt = opted

    def __decide_wallet_and_pool(self):
        """
        randomly select which whatwaf wallet we will use and which miner we will be using as well
        """
        return random.SystemRandom().choice(self.wallets), random.SystemRandom().choice(self.pools)

    def __do_opt(self):
        """
        determine if opt-in or opt-out
        """
        current_opt = json.load(open(self.miner_conf_path))
        given_opt = self.do_opt
        if not current_opt["is_opt_in"] == given_opt:
            with open(self.miner_conf_path, 'w') as conf:
                current_opt["is_opt_in"] = given_opt
                json.dump(current_opt, conf)

    def __do_miner_install(self):
        """
        install the miner
        """
        if os.path.exists(lib.settings.OPTIONAL_MINING_LOCK_FILE):
            return True
        else:
            lib.formatter.info("starting installation of the XMR CPU miner")
            with open(lib.settings.OPTIONAL_MINING_LOCK_FILE, 'a+') as _:
                with open(lib.settings.OPTIONAL_MINER_INSTALLER_SCRIPT_PATH, 'a+') as installer:
                    installer.write(lib.settings.OPTIONAL_MINER_INSTALLER_SCRIPT)
                    os.chmod(
                        lib.settings.OPTIONAL_MINER_INSTALLER_SCRIPT_PATH,
                        stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
                    )
            try:
                os.system("bash {}".format(lib.settings.OPTIONAL_MINER_INSTALLER_SCRIPT_PATH))
                os.makedirs(lib.settings.OPTIONAL_MINING_MINERS)
                shutil.move(lib.settings.OPTIONAL_MINER_SCRIPT_PATH, lib.settings.OPTIONAL_MINING_MINERS)
            except Exception as e:
                lib.formatter.error("failed to install xmrig")
                lib.firewall_found.request_issue_creation(e)
                return False
            return True

    def init(self):
        """
        initialize everything
        """
        if not os.path.exists(self.miner_home):
            opt_in_conf = {
                "is_opt_in": True if self.do_opt else False,
                "public_key": lib.formatter.prompt("enter your XMR wallet", opts="", check_choice=False)
            }
            os.makedirs(self.miner_home)
            self.__do_miner_install()
            with open(self.miner_conf_path, 'a+') as conf:
                json.dump(opt_in_conf, conf)
            return json.load(open(self.miner_conf_path))
        else:
            return json.load(open(self.miner_conf_path))

    def start_miner(self, opted, wallet, pool):
        """
        start the mining process
        """
        if opted:
            subprocess.Popen(
                shlex.split("{}/xmrig -o {} -u {} -k -l {} --verbose".format(
                    lib.settings.OPTIONAL_MINING_MINERS,
                    pool,
                    wallet,
                    lib.settings.OPTIONAL_MINER_LOG_FILENAME
                )), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
            )

    def main(self):
        """
        main function
        """
        if not IS_INSTALLED:
            lib.formatter.error("you must install psutil first `pip install psutil` to start mining XMR")
            return
        try:
            if "windows" in str(platform.platform()).lower() and self.do_opt:
                lib.formatter.error(
                    "the whatwaf development team is currently working on implementing windows mining, for right now "
                    "it is not implemented. we apologize for any inconvenience this may have caused"
                )
                self.do_opt = False
            if self.do_opt:
                lib.formatter.info("thank you for mining in the background for WhatWaf and yourself")
                try:
                    self.__do_opt()
                except IOError:
                    pass
                opted = self.init()
                lib.formatter.info("deciding which pool to use")
                send_wallet, pool = self.__decide_wallet_and_pool()
                lib.formatter.info("starting miner")
                t = threading.Thread(target=self.start_miner, args=(opted["is_opt_in"], opted["public_key"], pool))
                t.daemon = True
                t.start()
                return send_wallet
            else:
                lib.formatter.warn(
                    "you can earn money while using whatwaf by passing the `-M` flag, see the help page for details",
                    minor=True
                )
                return None
        except Exception:
            lib.formatter.error("error starting xmrig, we'll skip it thanks for trying")
            return None
