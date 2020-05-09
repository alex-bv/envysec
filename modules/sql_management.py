import datetime
import logging
import os
import pathlib
import sqlite3


class DBManager():
    """ Used to control databases.

    Available methods:
        public: __connect_db, __close_db, resolve_path, create_db
        private: -

    Dependencies:
        built-in: logging, os, pathlib, sqlite3
        3-d party: -
    """

    def __init__(self, logging_level = 30, database = './modules/database.sqlite3'):
        """ Manage SQL database.

        'database' - path to database with exclusions.
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')

        self.DBManager = logging.getLogger('DBManager')
        self.DBManager.debug('__init__: Initializing class...')

        self.DBManager.debug('__init__: Checking database existence...')
        self.database = pathlib.Path('.').resolve().joinpath(database)
        if self.database.exists() is True:
            self.DBManager.info('__init__: database found.')
        elif self.create_db() is False:
            self.DBManager.critical('__init__: database path {} not found!'.format(self.database))
            raise FileNotFoundError('Database path {} not found!'.format(self.database))
        else:
            self.DBManager.error('__init__: database path {} not found!'.format(self.database))
            self.DBManager.info('__init__: {} database created.'.format(self.database))

        self.DBManager.debug('__init__: Class initialized.')


    def __connect_db(self) -> bool:
        """ Connect to secEnvyronment database.
        To close connection use '__close_db';

        Default database filename is 'database.sqlite3' (./modules/database.sqlite3).
        Default database.sqlite3 have table 'Exclusion', 'Statistic'.
        """

        self.DBManager.info('__connect_db: Connecting to Exclude database...')
        self.DBManager.debug('__connect_db: Trying {} ...'.format(str(self.database)))

        if self.database.exists() is True:
            try:
                self.exclude_connect = sqlite3.connect(str(self.database))
                self.dbcursor = self.exclude_connect.cursor()
            except sqlite3.NotSupportedError as sql_bad_db_err:
                self.DBManager.warning('__connect_db: Wrong database type detected!')
                self.DBManager.debug('__connect_db: Database error log: {}'.format(str(sql_bad_db_err.args)))
                return False
            except sqlite3.DataError as sql_data_err:
                self.DBManager.warning('__connect_db: Database error occurred!')
                self.DBManager.debug('__connect_db: Database error log: {}'.format(str(sql_data_err.args)))
                return False
            except sqlite3.IntegrityError as sql_broken_db_err:
                self.DBManager.warning('__connect_db: Database integrity compromised.')
                self.DBManager.debug('__connect_db: Database error log: {}'.format(str(sql_broken_db_err.args)))
                return False
        else:
            self.DBManager.warning('__connect_db: Database does not exist or permissions denied.')
            self.DBManager.debug('__connect_db: Can\'t connect to {}'.format(str(self.database)))
            return False

        self.DBManager.debug('__connect_db: Connected.')
        return True

    def __close_db(self) -> bool:
        """ Close connection to secEnvyronment database.
        To open connection use __connect_db;

        Default database filename is 'database.sqlite3' (./modules/database.sqlite3).
        Default database.sqlite3 have table 'Exclusion', 'Statistic'.
        """

        self.DBManager.info('__close_db: Closing Database connection...')

        try:
            self.DBManager.debug('__close_db: Commiting...')
            self.exclude_connect.commit()
            self.DBManager.debug('__close_db: Closing database...')
            self.dbcursor.close()
        except sqlite3.ProgrammingError as sql_programming_err:
            self.DBManager.warning('__close_db: Programming error occurred!')
            self.DBManager.debug('__close_db: Database error log: {}'.format(str(sql_programming_err.args)))
            return False
        except sqlite3.OperationalError as sql_bad_operation_err:
            self.DBManager.warning('__close_db: Operational error occurred!')
            self.DBManager.debug('__close_db: Database error log: {}'.format(str(sql_bad_operation_err.args)))
            return False

        self.DBManager.debug('__close_db: Complete.')
        return True


    def create_db(self, structure = {'Exclusion': ['Path', 'Date'], 'Statistic': ['Found', 'Date', 'TotalReports']}) -> bool:
        """ Create database.

        Used to create sqlite database.

        Create database in 'self.database' path.
        The database structure is defined in 'structure'.
        Default structure is consist of 2 tables:
        'Exclusion', used to control user exclude list,
        'Statistic', used to store scan statistic.

        Table 'Exclusion' have 2 columns:
        'Path' - is a path to file or dir to be excluded from scan,
        'Date' - is a date exclusion were added.

        Table 'Statistic' have 3 columns:
        'Found' - is a path to file or dir to infected file,
        'Date' - is a date infected file were found,
        'TotalReports' - is a number of infected file reports.

        If database is already exists, return False.
        If database created but may not be connected, return False.
        If database created and available to connection, return True.
        """

        self.DBManager.debug('create_db: Initialize create_db...')

        def __create_command(structure: dict) -> str:
            """ Create SQL command to create structure.

            Structure is a dict, where:
            Keys are table names to be created,
            Values are columns to be created.

            Return command string.
            """

            self.DBManager.debug('create_db:__create_command: Creating command, received structure: {}'.format(structure))
            for table in structure:
                command = 'CREATE TABLE IF NOT EXISTS {} ('.format(table)
                for column in structure[table]:
                    command.join('{} VARCHAR (255) NOT NULL,')
                command.join(', PRIMARY KEY ({}))'.format(structure[table][0]))

                if table is not structure[-1]:
                    command.join(' / ')
            else:
                command.join(';')
                self.DBManager.debug('create_db:__create_command: Created command: {}'.format(command))
                return command

        self.DBManager.debug('create_db: Checking database existence.')
        if os.path.exists(self.database) is False:
            self.DBManager.warning('create_db: Database is not found!')
            self.DBManager.debug('create_db: Trying to create database:')

            self.DBManager.debug('create_db: Connecting...')
            db_connector = sqlite3.connect(self.database)
            self.DBManager.debug('create_db: Init cursor...')
            db_cursor = db_connector.cursor()
            self.DBManager.debug('create_db: Creating table...')
            db_cursor.execute(__create_command(structure)) # SQL
            self.DBManager.debug('create_db: Done without errors.')
        else:
            self.DBManager.info('create_db: Database is already exists.')
            return False

        self.DBManager.debug('create_db: Checking database.')
        if self.__connect_db() is True:
            self.DBManager.debug('create_db: Database check passed witout errors, closing.')
            self.__close_db()
            self.DBManager.debug('create_db: Database closed.')
        else:
            self.DBManager.error('create_db: Cannot connect database!')
            return False

        self.DBManager.debug('create_db: Database created.')
        return True

    def execute_db(self, command: str, values = None) -> bool:
        """ Execute SQL command.

        Default database structure is consist of 2 tables:
        'Exclusion', used to control user exclude list,
        'Statistic', used to store scan statistic.

        By default, table 'Exclusion' have 2 columns:
        'Path' - is a path to file or dir to be excluded from scan,
        'Date' - is a date exclusion were added.

        By default, table 'Statistic' have 3 columns:
        'Found' - is a path to file or dir to infected file,
        'Date' - is a date infected file were found,
        'TotalReports' - is a number of infected file reports.
        """

        self.DBManager.info('execute_db: Executing...') # TODO: make syntax to be alike cursor.execute('command (?)', value)
        if self.__connect_db() is True:
            try:
                self.DBManager.info('execute_db: Adding exception to database.') # TODO: make it yield output
                self.DBManager.debug('execute_db: Verifying path...')

                output = []
                if values != None and type(values) == tuple:
                    self.DBManager.debug('execute_db: executing {} with arguments {}'.format(command, values))
                    for out in self.dbcursor.execute(command, values): # SQL
                        output += out
                    self.DBManager.debug('execute_db: Executed;')
                elif type(values) != tuple:
                    self.DBManager.critical('execute_db: Cant execute command!')
                    self.DBManager.error('execute_db: Bad SQL values received: {}, turple should be received!'.format(values))
                    raise TypeError('execute_db: Bad SQL command arguments!')
                elif values == None:
                    self.DBManager.debug('execute_db: executing {} with no arguments.'.format(command))
                    for out in self.dbcursor.execute(command): # SQL
                        output += out
                    self.DBManager.debug('execute_db: Executed;')
                else:
                    self.DBManager.error('execute_db: Error ocuired, wont execute SQL command.')
                    self.DBManager.debug('execute_db: Bad SQL command: {}.'.format(command))

            except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
                self.DBManager.warning('execute_db: Failed execute SQL command.')
                self.DBManager.debug('execute_db: Database error log: {}'.format(str(sql_err.args)))
                if self.__close_db() is True:
                    self.DBManager.debug('execute_db: Database closed secessfully.')
                    return False
                else:
                    raise
            finally:
                self.DBManager.debug('execute_db: Database management complete.')
                self.__close_db()
                if self.__close_db() is True:
                    return (True, output)
        else:
            return False


    def resolve_path(self, path: str) -> str:
        """ Resolve path string to absolute path.

        'path' - is a path to file or dir (absolute or symlink) to be resolved.

        Used to resolve symlinks and return absolute path.
        """

        self.DBManager.info('resolve_path: Starting path resolver.')
        self.DBManager.debug('resolve_path: Resolving {}...'.format(path))

        try:
            path = pathlib.Path(path)
        except NotImplementedError as path_resolve_bad_python_err:
            self.DBManager.warning('resolve_path: Failed to resolve {}.'.format(path))
            self.DBManager.info('resolve_path: TIP: Probably OS is not supported.')
            self.DBManager.debug('resolve_path: NotImplementedError occurred, log: {}'.format(str(path_resolve_bad_python_err.args)))
            self.DBManager.info('resolve_path: Trying to run anyway...')
            return str(path)
        except TypeError as path_resolve_bad_os_err:
            self.DBManager.warning('resolve_path: Failed to resolve {}.'.format(path))
            self.DBManager.info('resolve_path: TIP: Probably wrong OS type detected.')
            self.DBManager.debug('resolve_path: TypeError occurred, log: {}'.format(str(path_resolve_bad_os_err.args)))
            self.DBManager.info('resolve_path: Trying to run anyway...')
            return str(path)
        finally:
            self.DBManager.debug('resolve_path: Path converted. Return {}'.format(str(path.expanduser().resolve())))
            return str(path.expanduser().resolve())



class ExcludeDB(DBManager):
    """ Used to manage 'Exclusion' table in database.

    Available methods:
        public: add_exception, remove_exception, get_exception
        private: -

    Dependencies:
        built-in: datetime, logging, os, pathlib, sqlite3
        3-d party: -
    """

    def __init__(self, logging_level = 30, database = './modules/database.sqlite3'):
        """ Manage exclude list.
        Exclude list is located in './modules/database.sqlite3', in table 'Exclusion'.
        'Path' is a primary key in 'Exclusion' table.

        'database' - path to database with exclusions.
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        DBManager.__init__(self, logging_level, database)

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')

        self.ExcludeDB = logging.getLogger('ExcludeDB')
        self.ExcludeDB.debug('__init__: Initializing class...')

        self.ExcludeDB.debug('__init__: Checking database existence...')
        self.database = pathlib.Path('.').resolve().joinpath(database)
        if self.database.exists() is True:
            self.ExcludeDB.info('__init__: database found.')
        elif DBManager.create_db(self) is False:
            self.ExcludeDB.critical('__init__: database path {} not found!'.format(self.database))
            raise FileNotFoundError('Database path {} not found!'.format(self.database))
        else:
            self.ExcludeDB.error('__init__: database path {} not found!'.format(self.database))
            self.ExcludeDB.info('__init__: {} database created.'.format(self.database))

        self.ExcludeDB.debug('__init__: Class initialized.')


    def add_exception(self, path: str) -> bool:
        """ Add path to exclude list.
        Exclude list is located in './modules/database.sqlite3', in table 'Exclusion'.

        'path' - is a path to file or folder to be added to exclude list.

        Used to connect and add path to 'database.sqlite3'.
        If 'Path' added, date will be automatically appended into table.
        """

        self.ExcludeDB.info('add_exception: Adding exception...')
        path = DBManager.resolve_path(self, path)

        try:
            self.ExcludeDB.info('add_exception: Adding exception to database.')
            self.ExcludeDB.debug('add_exception: Verifying path...')
            if os.path.exists(path) is True:
                self.ExcludeDB.debug('add_exception: Add exception: {}'.format(path))
                DBManager.execute_db("INSERT INTO Exclusion(Path) VALUES (?, ?)", values = (path, datetime.datetime.now(),)) # SQL
            else:
                self.ExcludeDB.warning('add_exception: {} does not exists;'.format(path))
                return False
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('add_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('add_exception: Database error log: {}'.format(str(sql_err.args)))
            return False
        finally:
            self.ExcludeDB.debug('add_exception: Database management complete.')
            return True

    def remove_exception(self, path: str) -> bool:
        """ Remove path from exclude list.
        Exclude list is located in './modules/database.sqlite3', in table 'Exclusion'.

        'path' - is a path to file or folder to be removed from exclude list.

        Used to connect and remove path from 'database.sqlite3'.
        'Path' is a primary key in 'Exclusion' table.
        """

        self.ExcludeDB.info('remove_exception: Removing exception...')
        path = DBManager.resolve_path(self, path)

        try:
            self.ExcludeDB.info('remove_exception: Removing {} from database.'.format(path))
            self.ExcludeDB.debug('remove_exception: Trying to remove exception: {}'.format(path))

            for out in DBManager.execute_db("SELECT 1 FROM Exclusion WHERE Path=(?);", values = (path,)): # SQL
                if out == (1,):
                    DBManager.execute_db("DELETE FROM Exclusion WHERE Path=(?);", values = (path,)) # SQL
                    self.ExcludeDB.info('remove_exception: {} successfully removed.'.format(path))
                else:
                    self.ExcludeDB.warning('remove_exception: Failed to remove {} from database.'.format(path))
                    self.ExcludeDB.info('remove_exception: {} not in database.'.format(path))
                    return False
        except(sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('remove_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('remove_exception: Database error log: {}'.format(str(sql_err.args)))
            return False
        finally:
            self.ExcludeDB.debug('remove_exception: Database management complete.')
            return True

    def get_exception(self) -> list:
        """ Get all items in exclude list.

        Used to connect and get list from 'database.sqlite3'.

        Executing 'for ... in ... SELECT * FROM Exclusion' will return tuple;
        By design, only 1 object in tuple will be counted, other will be skipped.
        Yielding first item in a tuple 'item[0]'.

        Return None if database error occurred.
        """

        self.ExcludeDB.info('get_exception: Getting exceptions...')
        exclude_list = list()

        try:
            self.ExcludeDB.debug('get_exception: Getting exclude list;')
            for row in DBManager.execute_db("SELECT * FROM Exclusion;"): # SQL
                self.ExcludeDB.info('get_exception: In exclude: {}, {}'.format(row[0], row[1]))
                self.ExcludeDB.debug('get_exception: Raw exception line: {}'.format(str(row)))
                exclude_list += [row[0]] # TODO: make both values (path and time) packed
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('get_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('get_exception: Database error log: {}'.format(str(sql_err.args)))
            return []
        finally:
            self.ExcludeDB.debug('get_exception: Database management complete.')
            if exclude_list != []:
                return exclude_list
            else:
                return []
