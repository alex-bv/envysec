import datetime
import logging
import os
import pathlib
import queue
import sqlite3
import subprocess
import threading


class ClamAV():
    """ ClamAV command class. This is not a stand-alone scanner.
    It depends on original ClamAV and used to perform an easier-control.

    Required packages (dependencies): 
        built-in: datetime, logging, os, queue, subprocess, threading, sqlite3, pathlib

    To perform a scan, it uses sys.Popen to call for a ClamAV bin with a customized args.
    For storring exlclude database uses sqlite3.

    ClamAV official site (2018): www.clamav.net
    Cisco (ClamAV owner and maintainer) official site (2018): www.cisco.com
    """

    def __init__(self, config: dict, logging_level = 30):
        """ ClamAV class used to control ClamAV app.

        config -- dictionary with paths to ClamAV bins (freshclam & clamscan);
        logging_level -- verbosity of logging (0 - debug, 30 - warnings. See logging docs)
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')
        
        self.ClamLog = logging.getLogger('ClamAV')
        self.ClamLog.debug('__init__: Initializing class...')

        self.configuration = config
        self.clamav_queue = queue.Queue()

        self.ClamLog.debug('__init__: Class initialized.')


    def scan(self, targets: list, args = ['-i', '-r', '--no-summary']) -> "yield str":
        """ Method used to perform a ClamAV scan.

        targets -- list of paths to be scanned;
        args -- list of arguments to be sent to ClamAV;

        Return False if file/dir (target) does not exists, might not be accessed
        or in exclude list (see config).
        If target exist and not in exclude list, it will call for ClamAV
        and yield it\'s output.

        Argument target is a file or dir to be scanned.
        Args are arguments list to be sent to ClamAV bin
        (see ClamAV documentations for more).

        Default scanner behaveour is (arguments descriptions):
            show only infected files (-i). It also will show all files, that might not be accessed by ClamAV;
            scan recursively (-r). It usefull for scanning whole dir;
            do not show summary at the end of scan (--no-summary).
        """

        def __parse_line(line: str) -> bool:
            """ Check if line report thread found.
            Line must ends with 'FOUND' and starts with path to infected file.

            Return True if both conditions are met, else return False.
            """

            self.ClamLog.debug('scan: __parse_line: Checking {}'.format(line))
            if line.endswith(' FOUND\r\n') is True and os.path.exists(line.split(': ')[0]) is True:
                self.ClamLog.debug('scan: __parse_line: {} met conditions, return True.'.format(line))
                return True
            else:
                self.ClamLog.debug('scan: __parse_line: {} have not met conditions, return False.'.format(line))
                return False

        self.ClamLog.debug('scan: Starting scan.')

        for target in targets:
            args.insert(0, self.__resolve_path(target))

            if os.path.exists(args[0]) is False:
                self.ClamLog.info('scan: {} is not exists, so could not be scanned.'.format(str(args[0])))
                raise FileNotFoundError('File {} not found or permission denied.'.format(args[0]))
            elif args[0] in self.get_exception():
                self.ClamLog.info('scan: {} is in exclude list.'.format(str(args[0])))
                return str('')

        for line in self.__start_work(self.__scan, args = args):

            self.ClamLog.debug('scan: Init __parse_line...')
            if __parse_line(line) is True:
                self.ClamLog.debug('scan: __parse_line: line reports True.')
                self.ClamLog.warning('scan: FOUND: {}'.format(str(line)))
                yield line
            else:
                self.ClamLog.debug('scan: __parse_line: line reports False.')
                self.ClamLog.warning('unknown line: {}'.format(str(line)))

    def update(self, args = None) -> "yield output":
        """ Method used to perform a ClamAV database update.

        It yield\'s ClamAV Update output.

        Args are arguments list to be sent to ClamAV bin
        (see ClamAV documentations for more).

        For more information about ClamAV, see ClamAV documentations.
        """

        self.ClamLog.info('update: ClamAV Update started.')
        for line in self.__start_work(self.__update, args=args):
            self.ClamLog.info(line.strip())
            yield line


    def __scan(self, *args) -> bool:
        """ 'Lower-level' method (module) of scan. 
        Method used to call for ClamAV scanner bin.
        It fact, it used to call for ClamAV bin (for example: clamscan.exe on Windows)
        and put it\'s output to pipe.
        
        Return True if scan complete successfully.
        Raise OSError if OS or memory errors occurred.
        Raise ValueError if wrong internal arguments or wrong bin\'s path received.

        Args are arguments list to be sent to ClamAV bin.
        Available arguments might be found at ClamAV scan documentations or by using --help.
        """

        self.ClamLog.debug('__scan: Scan started.')
        args = list(args)
        
        try:
            with subprocess.Popen([self.configuration["Scanner"]] + args, stdout=subprocess.PIPE) as scanp:
                self.ClamLog.debug('__scan: Subprocess opened. (subprocess.Popen)')
                for line in iter(scanp.stdout.readline, b''):
                    self.clamav_queue.put(line)
        except MemoryError as merr:
            self.ClamLog.critical('__scan: Failed to perform __scan. Probably not enough memory.')
            self.ClamLog.debug('__scan: MemoryError arguments: ' + str(merr.args))
            raise OSError('System may not perform scan, probably not enough memory.', merr.args)
        except OSError as oserr:
            self.ClamLog.critical("""__scan: Failed to call for __scan. Probably, module subprocess.Popen 
                                 received wrong bin\'s filename.""")
            self.ClamLog.debug('__scan: OSError arguments: ' + str(oserr.args))
            raise ValueError('System may not perform scan, probably not system error raised.', oserr.args)
        except ValueError as verr:
            self.ClamLog.critical("""__scan: Failed to call for __scan. Probably, module subprocess.Popen 
                                called with invalid arguments.""")
            self.ClamLog.debug('__scan: ValueError arguments: ' + str(verr.args))
            raise ValueError('Failed to spawn process, probably wrong internal arguments received.', verr.args)
        else:
            self.ClamLog.debug('__scan: Scan done.')
            return True

    def __update(self, *args) -> bool:
        """ 'Lower-level' database (signatures) update method.
        It call for update bin, bin's path taken from configuration.
        It fact, it used to call for ClamAV bin (for example: freshclam.exe on Windows)
        and put it\'s output to pipe.

        Return True if update complete successfully.
        Raise OSError if OS or memory errors occurred.
        Raise ValueError if wrong internal arguments or wrong bin\'s path received.

        Args are arguments list to be sent to ClamAV bin.
        Available arguments might be found at ClamAV update documentations or by using --help.
        """

        self.ClamLog.debug('__update: Update in fact started.')
        args = list(args)

        try:
            with subprocess.Popen([self.configuration["Updater"]] + args, stdout=subprocess.PIPE) as updatep:
                self.ClamLog.debug('__update: Subprocess opened. (subprocess.Popen)')
                for line in iter(updatep.stdout.readline, b''):
                    self.clamav_queue.put(line)
        except OSError as oserr:
            self.ClamLog.critical("""__update: Failed to call for __update. Probably, module subprocess.Popen 
                                received wrong bin\'s filename.""")
            self.ClamLog.debug('__update: OSError arguments: ' + str(oserr.args))
            raise ValueError('Failed to spawn process, probably wrong bin\'s filename received.', oserr.args)
        except ValueError as verr:
            self.ClamLog.critical("""__update: Failed to call for __update. Probably, module subprocess.Popen 
                                called with invalid arguments.""")
            self.ClamLog.debug('__update: ValueError arguments: ' + str(verr.args))
            raise ValueError('Failed to spawn process, probably wrong internal arguments received.', verr.args)
        except MemoryError as merr:
            self.ClamLog.critical('__update: Failed to perform __update. Probably not enough memory.')
            self.ClamLog.debug('__update: MemoryError arguments: ' + str(merr.args))
            raise MemoryError('System may not perform update, probably not enough memory.', merr.args)
        else:
            self.ClamLog.debug('__update: Update done.')
            return True


    def __start_work(self, work: 'function', args = None) -> "yield str":
        """ Initialize main work thread.
        It used to call for main working function (like scan or update).

        work -- name of function to be called.
        args -- list of arguments to be sent to work function.

        Yield work\'s function output.
        """

        self.ClamLog.debug('__start_work: Initialize work tread.')
        if args is None:
            args = list()

        work_thread = threading.Thread(target=work, args=args, daemon = True)
        work_thread.start()
        self.ClamLog.debug('__start_work: Work tread Initialized.')

        while work_thread.is_alive():
            try:
                line = self.clamav_queue.get_nowait()
                line = line.decode('utf-8').replace('\n', '')
            except queue.Empty:
                pass
            else:
                yield line


    def __resolve_path(self, path: str) -> str:
        """ Resolve path string to absolute path.

        Used to resolve symlinks and return absolute path.
        """

        self.ClamLog.info('__resolve_path: Starting path resolver.')
        self.ClamLog.debug('__resolve_path: Resolving {}...'.format(path))

        try:
            path = pathlib.Path(path)
        except NotImplementedError as prnie:
            self.ClamLog.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ClamLog.info('__resolve_path: TIP: Probably OS is not supported.')
            self.ClamLog.debug('__resolve_path: NotImplementedError occurred, log: ' + str(prnie.args))
            self.ClamLog.info('__resolve_path: Trying to run anyway...')
            return str(path)
        except TypeError as prte:
            self.ClamLog.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ClamLog.info('__resolve_path: TIP: Probably wrong OS type detected.')
            self.ClamLog.debug('__resolve_path: TypeError occurred, log: ' + str(prte.args))
            self.ClamLog.info('__resolve_path: Trying to run anyway...')
            return str(path)
        finally:
            self.ClamLog.debug('__resolve_path: Path converted. Return {}'.format(str(path.expanduser().resolve())))
            return str(path.expanduser().resolve())

    
    ## SQL Database management;

    def __connect_db(self) -> bool:
        """ Connect to ClamAV exclude database.
        To close connection use __close_db;

        Used to control ClamAV scan output;

        Default exclude.db have to have single table 'exclude'.
        Exclude database filename is 'exclide.db' (secEnvyronment/modules/exclude.db).
        """

        self.ClamLog.info('__connect_db: Connecting to Exclude database...')

        db_path = pathlib.Path(os.path.abspath(os.path.dirname(__file__))).resolve().joinpath('exclude.db')
        self.ClamLog.debug('__connect_db: Checking database existence...')
        self.ClamLog.debug('__connect_db: Trying {} ...'.format(str(db_path)))

        if os.path.exists(db_path) is True:
            try:
                self.__exclude_connect = sqlite3.connect(str(db_path))
                self.__dbcursor = self.__exclude_connect.cursor()
            except sqlite3.NotSupportedError as sqlnserr:
                self.ClamLog.warning('__connect_db: Wrong database type detected!')
                self.ClamLog.debug('__connect_db: Database error log: ' + str(sqlnserr.args))
                return False
            except sqlite3.DataError as sqldbe:
                self.ClamLog.warning('__connect_db: Database error occurred!')
                self.ClamLog.debug('__connect_db: Database error log: ' + str(sqldbe.args))
                return False
            except sqlite3.IntegrityError as sqlintege:
                self.ClamLog.warning('__connect_db: Database integrity compromised.')
                self.ClamLog.debug('__connect_db: Database error log: ' + str(sqlintege.args))
                return False
        else:
            self.ClamLog.warning('__connect_db: Database does not exist or permissions denied.')
            self.ClamLog.debug('__connect_db: Can\'t connect to {}'.format(str(db_path)))
            return False

        self.ClamLog.debug('__connect_db: Connected.')
        return True

    def __close_db(self) -> bool:
        """ Close connection to ClamAV exclude database.
        To open connection use __connect_db;

        Used to control ClamAV scan output;

        Default exclude.db have to have single table 'exclude'.
        Exclude database filename is 'exclide.db' (secEnvyronment/modules/exclude.db).
        """

        self.ClamLog.info('__close_db: Closing Database connection...')

        try:
            self.ClamLog.debug('__close_db: Commiting...')
            self.__exclude_connect.commit()
            self.ClamLog.debug('__close_db: Closing database...')
            self.__dbcursor.close()
        except sqlite3.ProgrammingError as sqlprerr:
            self.ClamLog.warning('__close_db: Programming error occurred!')
            self.ClamLog.debug('__close_db: Database error log: ' + str(sqlprerr.args))
            return False
        except sqlite3.OperationalError as sqloperr:
            self.ClamLog.warning('__close_db: Operational error occurred!')
            self.ClamLog.debug('__close_db: Database error log: ' + str(sqloperr.args))
            return False

        self.ClamLog.debug('__close_db: Complete.')
        return True


    def add_exception(self, path: str) -> bool:
        """ Add path to exclude list.

        path -- is a (string) path to file/folder.

        Used to connect and add path to 'exclude.db'.
        """

        self.ClamLog.info('add_exception: Adding exception...')
        self.__connect_db()
        path = self.__resolve_path(path)

        try:
            self.ClamLog.info('add_exception: Adding exclude to database.')
            self.ClamLog.debug('add_exception: Verifying path...')
            if os.path.exists(path) is True:
                self.ClamLog.debug('add_exception: Add exclude: {}'.format(str(path)))
                self.__dbcursor.execute("INSERT INTO exclude(path) VALUES (?)", (path,))
            else:
                self.ClamLog.warning('add_exception: {} does not exist;'.format(str(path)))
                self.__close_db()
                return False
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sqle:
            self.ClamLog.warning('add_exception: Failed execute SQL command.')
            self.ClamLog.debug('add_exception: Database error log: ' + str(sqle.args))
            self.__close_db()
            return False
        finally:
            self.ClamLog.debug('add_exception: Database management complete.')
            self.__close_db()
            return True

    def remove_exception(self, path: str) -> bool:
        """ Remove path from exclude list.

        path -- is a (string) path to file/folder.

        Used to connect and remove path from 'exclude.db'.
        """

        self.ClamLog.info('remove_exception: Removing exception...')
        self.__connect_db()
        path = self.__resolve_path(path)

        try:
            self.ClamLog.info('remove_exception: Removing exclude from database.')
            self.ClamLog.debug('remove_exception: Trying to remove exclude: {}'.format(str(path[0])))

            for out in self.__dbcursor.execute("SELECT 1 FROM exclude WHERE path=(?)", (path,)):
                if out == (1,):
                    self.__dbcursor.execute("DELETE FROM exclude WHERE path =(?)", (path,))
                    self.ClamLog.info('remove_exception: {} successfully removed.'.format(str(path)))
                else:
                    self.ClamLog.warning('remove_exception: Failed to remove {} from database.'.format(str(path)))
                    self.ClamLog.info('remove_exception: {} not in database.'.format(str(path)))
                    self.__close_db()
                    return False
        except(sqlite3.ProgrammingError, sqlite3.OperationalError) as sqle:
            self.ClamLog.warning('remove_exception: Failed execute SQL command.')
            self.ClamLog.debug('remove_exception: Database error log: ' + str(sqle.args))
            self.__close_db()
            return False
        finally:
            self.ClamLog.debug('remove_exception: Database management complete.')
            self.__close_db()
            return True

    def get_exception(self) -> list:
        """ Get all items in exclude list.

        Used to connect and get list from 'exclude.db'.

        Executing 'for ... in ... SELECT * FROM exclude' will return turple;
        By design, only 1 object in turple will be counted, other will be skipped.
        Yielding first item in a turple 'item[0]'.

        Return None if database error occurred.
        """

        self.ClamLog.info('get_exception: Getting exceptions...')
        self.__connect_db()
        exclude_list = list()
        
        try:
            self.ClamLog.debug('get_exception: Getting exclude list;')
            for row in self.__dbcursor.execute("SELECT * FROM exclude;"):
                self.ClamLog.debug('get_exception: In exclude: {}'.format(str(row[0])))
                self.ClamLog.debug('get_exception: Raw exception line: ' + str(row))
                exclude_list += [row[0]]
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sqle:
            self.ClamLog.warning('get_exception: Failed execute SQL command.')
            self.ClamLog.debug('get_exception: Database error log: ' + str(sqle.args))
            self.__close_db()
            return []
        finally:
            self.ClamLog.debug('get_exception: Database management complete.')
            self.__close_db()
            
            if exclude_list is not None:
                return exclude_list
            else:
                return []
