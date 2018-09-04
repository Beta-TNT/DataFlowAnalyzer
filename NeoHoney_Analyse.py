import collections
import NeoHoney_TypeLib
from abc import ABCMeta, abstractmethod
from AnalyseLib import AnalyseBase
import pymongo


__author__ = 'Beta-TNT'


class NeoHoneyAnalyserPluginInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def AnalyseData(self, InputData, InputExtraData):
        pass

    @abstractmethod
    def FlagGenerator(self, InputData, InputRule):
        pass

    @abstractmethod
    def Tweak(self):
        pass

    @property
    def PluginName(self):
        pass

    @property
    def PluginInstructions(self):
        pass

    @property
    def PluginProperties(self):
        pass


class NeoHoneyAnalyser(AnalyseBase):
    'Neo-Honey蜜罐用分析引擎类'
    # 默认输入数据符合监控数据的字段规范

    _blackList = dict()
    # 路径/SessionID - Set[EventItem]关联。
    # Key:SessionID或'HoneyID:FileName'，如："1001:C:\Windows\explorer.exe""1001#1244#1501233210"。
    # Value：已经落地的EventItem对象集合Set
    _events = dict()        # 事件ID——EventItem关联，Key是EventID，Value是对应的EventItem 目前还没有实际用途
    _plugins = dict()       # 插件对象集合
    _rulesDict = dict()    # 按数据类型（DataType）存放的分类好的规则列表
    # 原版实现里的SessionID-进程行为队列缓存丢弃，分析引擎不再记录未触发任何规则的进程的行为队列，只记录触发前序规则之后到触发关键规则之间的行为
    # 回溯行为请查阅原始数据，规则字段trackable（可回溯）废除
    # 原版实现里的文件路径-EventIDs缓存丢弃，功能合并到_blackList缓存里
    # 原版实现里的Flag-EventItem缓存使用算法基类的_cache实现

    # 输入数据字段约定
    # DataType：数据类型名称，也是数据库表名
    # 其余字段：以对应数据库表字段名和数据类型为准

    # 为基类规则增加以下字段：
    # RuleName：规则名称
    # DataType：匹配的蜜罐数据类型
    # AttackType：攻击类型，写入数据库event_main表AttackType字段
    # Level：事件等级，参考syslog的日志等级
    # ContentLine：规则命中后输出的文本内容，写入event_detail的EventMark字段
    # IsCritical：是否关键规则，触发关键规则后准事件将写入数据库落地为事件
    # PluginName：调用的插件名称
    # PluginArgus：调用插件时的参数内容

    # 定义EventItem，作为CacheItem的ExtraData字段内容，包含以下字段：
    # HoneyID：产生事件的蜜罐机ID
    # EventID：事件在数据库里的ID，没有落地时为0
    # EventDataQueue：事件数据队列，在事件落地的时候写入event_detail表
    # EventContentText：事件描述，由触发规则的ContentLine构
    # SuspeciousPath：可疑文件路径
    # Level：事件分数
    # StartTimestamp：事件起始时间戳
    # StartSessionID：事件起始进程的SessionID
    # StartProcessName：事件起始进程名
    # AttackType：事件类型，由触发规则的AttackType定义

    __MongoDbServer = ''
    __MongoDbPort = 27017
    __MongoDbLogin = ''
    __MongoDbPassword = ''
    __MongoDbDataBaseName = 'NeoHoney'
    __MongoDbCollectionName = 'events'

    __MongoDbConn = None
    __MongoDbColl = None

    def __init__(self,
                 Rules,
                 MongoDbServer,
                 MongoDbPort,
                 MongoDbLogin,
                 MongoDbPassword,
                 MongoDbDataBaseName):
        self._rules = Rules
        __MongoDbServer = MongoDbServer
        __MongoDbPort = MongoDbPort
        __MongoDbLogin = MongoDbLogin
        __MongoDbPassword = MongoDbPassword
        __MongoDbDataBaseName = MongoDbDataBaseName
        
        for rule in Rules:
            ruleSet = self._rulesDict.get(rule['DataType'])
            if ruleSet == None:
                self._rulesDict[rule['DataType']] = list()
            self._rulesDict[rule['DataType']].append(rule)

        # dbConnectionStr = "mongodb://%s:%s@%s:%d/" % (MongoDbLogin, MongoDbPassword, MongoDbServer, MongoDbPort)
        self.__MongoDbConn = pymongo.MongoClient(MongoDbServer, MongoDbPort)
        self.__MongoDbColl = self.__MongoDbConn.NeoHoney.events

    class EventItem(object):
        _HoneyID = 0
        _EventID = None
        _EventContentText = ''
        _Level = 0
        _StartTimestamp = 0
        _StartSessionID = ''
        _StartProcessName = ''
        _AttackType = ''

        # 行为缓存队列，仅在命中入口点规则之后开始使用。使用约定：左进(AppendLeft)右出（Pop）
        _EventDataQueue = collections.deque()

        def AppendContentLine(self, InputText):
            self._EventContentText += (InputText + '\n\r')

        @property
        def EventContentText(self):
            return self._EventContentText

        @property
        def EventDataQueue(self):
            return self._EventDataQueue

        @property
        def HoneyID(self):
            return self._HoneyID

        @property
        def EventID(self):
            return self._EventID

        @EventID.setter
        def EventID(self, value):
            self._EventID = value

        @property
        def Level(self):
            return self._Level

        @Level.setter
        def Level(self, value):
            self._Level = value

        @property
        def AttackType(self):
            return self._AttackType

        @AttackType.setter
        def AttackType(self, value):
            self._AttackType = value

        def __init__(self, HoneyID, StartTimeStamp, StartSessionID, StartProcessName, AttackType):
            self._HoneyID = HoneyID
            self._StartTimestamp = StartTimeStamp
            self._StartSessionID = StartSessionID
            self._StartProcessName = StartProcessName
            self._AttackType = AttackType

    def __PluginFunc(self, InputPluginName, InputData, PluginArgus):
        '执行插件功能。输入插件名、监控数据以及插件参数，返回插件运算结果'
        HitPlugin = self._plugins.get(InputPluginName, None)
        if HitPlugin != None:
            rtn = True
            # TODO: 完成插件功能执行
            return rtn
        else:  # 忽略无效的插件名
            return True

    @staticmethod
    def CovertToSimple(InputData, InputEventMark=''):
        '将不同数据结构的监控数据转换成可存入event_detail表的简化型数据'
        # 已弃用
        if type(InputData) != dict:
            raise TypeError("Invaild InputData Type, expecting dict.")

        if 'DataType' not in InputData:
            raise Exception(
                "InputData not vaild, expecting \'DataType\' field.")

        if InputData['DataType'] in {'ThreadInfo', 'MemoryInfo', 'RegInfo', 'QueryInfo'}:
            # 忽略对事件分析用处不大但很冗余的数据
            return None

        rtn = dict()
        rtn['HoneyID'] = InputData['HoneyID']
        rtn['SessionID'] = InputData['SessionID']
        rtn['Timestamp'] = InputData['Timestamp']
        rtn['DataType'] = InputData['DataType']
        rtn['EventMark'] = InputEventMark
        rtn['ProcessName'] = InputData['ProcessName']
        # SampleInfo表没有OpCode和OpFlag字段，略过
        if InputData['DataType'] != 'SampleInfo':
            rtn['OpCode'] = InputData['OpCode']
            rtn['OpFlag'] = InputData['OpFlag']

        if InputData['DataType'] == 'SampleInfo':
            # SampleInfo数据，OpData存放样本文件原路径，ExtraData字段是样本MD5
            rtn['OpData'] = InputData['SampleName']
            rtn['ExtraData'] = InputData['MD5']

        elif InputData['DataType'] == 'FileInfo':
            # FileInfo数据，OpData存放目标文件路径
            rtn['OpData'] = InputData['OpFilePath']
            if InputData['OpCode'] == NeoHoney_TypeLib.FileInfoOp.FLEM_RENAME_FILE:
                # 重命名操作，ExtraData存放重命名之后的新文件名
                rtn['ExtraData'] = NeoHoney_TypeLib._WChar2String(
                    InputData['OpData'])
            elif InputData['OpCode'] == NeoHoney_TypeLib.FileInfoOp.FLEM_SET_ATTRIBUTES:
                # 修改文件属性，ExtraData存放文件修改后的FILE_BASIC_INFOMATION结构体二进制
                rtn['ExtraData'] = InputData['OpData']

        elif InputData['DataType'] == 'ProcInfo':
            # ProcInfo数据
            if InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_PROCESS_CREATE:
                # 进程创建：OpData存放新进程的路径和进程启动参数，ExtraData字段是新进程的SessionID
                rtn['OpData'] = '%s %s' % (
                    InputData['OpProcessName'], InputData['OpProcessParam'])
                rtn['ExtraData'] = '%d#%d#%d' % (
                    InputData['HoneyID'], InputData['OpPID'], InputData['Timestamp'])
            elif InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_PROCESS_TERMINATE:
                # 进程被终结，OpData存放被终结的进程完整路径，ExtraData存放被终结的进程的SessionID
                rtn['OpData'] = InputData['OpProcessName']
                rtn['ExtraData'] = InputData['OpProcessParam']
            else:
                return None

        elif InputData['DataType'] == 'ConsoleInfo':
            # ConsoleInfo数据，OpData存放内容字符串（包括DNS、URL、控制台输入和输出）
            rtn['OpData'] = InputData['ContentString']

        elif InputData['DataType'] == 'ModuleInfo':
            # ModuleInfo数据，只记录加载模块数据，OpData是加载的模块的文件路径
            if InputData == NeoHoney_TypeLib.ProcInfoOp.PRCM_MODULE_LOAD:
                rtn['OpData'] = InputData['ModulePath']
            else:
                return None

        elif InputData['DataType'] == 'NetInfo':
            # NetInfo数据
            if InputData['OpCode'] == NeoHoney_TypeLib.NetInfoOp.TDIM_COMMON:
                # 将网络监控数据简化合并成可读的格式
                # 合并后的解析方法：按空格分隔OpData字段内容：
                #   [0]: 协议名（'TCP', 'UDP', 'ICMP', 'Undefined'）如果第一个串不是这四个子串之一，那就不用继续下去了
                #   [1]: 本端IP:本端端口
                #   [2]: 数据包流入（'<-'）或者数据包流出（'->'）
                #   [3]: 远端IP:远端I端口
                #   [4]: 数据包字节数
                #   [5]: 'byte(s)'
                if InputData['Direction'] == NeoHoney_TypeLib.NetInfoDirection.PACK_IN:
                    # 数据包接收，OpData内容是[协议名 本地（目的）IP:本地（目的）端口 <- 远程（源）IP:远程（源）端口 包长度 byte(s)]
                    # 例如：TCP 192.168.0.1:52139 <- 192.168.1.1:80 100 byte(s)
                    rtn['OpData'] = "%s %s:%d <- %s:%d %d byte(s)" % (
                        InputData['Protocol'],
                        InputData['DstIP'],
                        InputData['DstPort'],
                        InputData['SrcIP'],
                        InputData['SrcPort'],
                        InputData['PacketLength'])
                elif InputData['Direction'] == NeoHoney_TypeLib.NetInfoDirection.PACK_OUT:
                    # 数据包发送，OpData内容是[协议名 本地（源）IP:本地（源）端口 -> 远程（目的）IP:远程（目的）端口 包长度 byte(s)]
                    # 例如：TCP 192.168.0.1:52139 -> 192.168.1.1:80 100 byte(s)
                    rtn['OpData'] = "%s %s:%d -> %s:%d %d byte(s)" % (
                        InputData['Protocol'],
                        InputData['SrcIP'],
                        InputData['SrcPort'],
                        InputData['DstIP'],
                        InputData['DstPort'],
                        InputData['PacketLength'])
            elif InputData['OpCode'] in {NeoHoney_TypeLib.NetInfoOp.TDIM_HTTP, NeoHoney_TypeLib.NetInfoOp.TDIM_QUERY_DNS}:
                # URL访问和DNS监控，OpData是URL或者域名内容
                rtn['OpData'] = NeoHoney_TypeLib._Char2String(
                    InputData['ContentBin'])

        else:
            return None

        return rtn

    def _InsertEventDetailData(self, InputData, EventID, EventMark = ''):
        '将详细数据插入event_detail表，或者其他和事件相关的数据集里'
        # TODO: 完成该部分功能
        # EventID 输入的是ObjectID对象
        InputData['EventMark'] = EventMark
        self.__MongoDbColl.update_one({'_id': EventID},{'$push':{'DetailData':InputData}})
        pass

    def _InsertNewEvent(self, InputData, InputLevel, InputAttackType, InputEventContent):
        '将事件数据落地，返回构造的新事件在数据库里的ID'
        # TODO: 完成该部分内容
        rtn = None
        insertItems = dict()
        insertItems['HoneyID'] = InputData['HoneyID']
        insertItems['StartTime'] = InputData['Timestamp']
        insertItems['SessionID'] = InputData['SessionID']
        insertItems['ProcessName'] = InputData['ProcessName']
        insertItems['AttackType'] = InputAttackType
        insertItems['Content'] = InputEventContent
        insertItems['Level'] = InputLevel
        insertItems['DetailData'] = list()
        rtn = self.__MongoDbColl.insert_one(insertItems).inserted_id
        print('New event inserted.\n')
        print('Event content: %s\n' % InputEventContent)
        print('Event ID: %s\n' % rtn)
        return rtn

    def FlagGenerator(self, InputData, InputTemplate):
        # 重写父类的FlagGenerator函数，扩展占位符支持
        rtn = InputTemplate
        if InputData['DataType'] == 'ProcInfo' and InputData['OpCode'] == 0:
            # 创建新进程，增加{OpSessionID}占位符，内容是新建进程的SessionID
            rtn.replace("{OpSessionID}", "%d#%d#%d" % (InputData['HoneyID'], InputData['OpPID'], InputData['Timestamp']))
        return self._DefaultFlagGenerator(InputData,rtn)
    

    
    def SingleRuleTest(self, InputData, InputRule):
        '重写父类的默认的单规则匹配函数，将不匹配的数据类型过滤掉'
        if InputData['DataType'] == InputRule['DataType']:
            return self._DefaultSingleRuleTest(InputData, InputRule)
        else:
            return (False, None)

    def _RuleTriggered(self, InputData, Rule, HitItem, CurrentFlag):
        '规则命中后执行的函数，实现插件运行、事件追踪、黑名单进程缓存管理以及数据入库等功能'
        # 插件功能入口也将在这一层实现。在数据处理阶段之前完成插件判定
        # 触发关键规则，EventItem的Level和AttackType字段要改写为关键规则的Level和AttackType内容后再入库
        # 函数返回值是和数据相关联的EventItem（已有或新建）。
        # 如果规则和插件匹配的结果是无法关联，返回None。算法层将自动忽略，不再进行Flag关联

        if 'PluginName' in Rule:  # 如果插件名存在而且不为空，先运行插件，根据结果决定是否进行余下的业务流程
            PluginArgus = Rule.get('PluginArgus', None)
            # 如果插件返回False，忽略该数据
            if not self.__PluginFunc(Rule['PluginName'], InputData, PluginArgus):
                return None

        rtnEventItem = None

        if bool(HitItem):
            # 命中数据不为None，说明匹配到了一个已经存在的事件，需要检查EventItem的EventID判断是否是落地入库的事件
            rtnEventItem = HitItem.ExtraData
            if bool(rtnEventItem.EventID):
                # EventID不为0或者None，说明通过规则匹配之后还命中了一个已经落地的事件。用于追踪事件的规则会进入这个分支
                # 数据入库之后将该Flag关联到此次命中的EventItem
                self._InsertEventDetailData(InputData, rtnEventItem.EventID, self.FlagGenerator(
                    InputData, Rule['ContentLine']))
                # 入库完成后直接返回，跳过追加事件数据和关键规则判定阶段：
                # 即便是关键规则，匹配到一个已经落地的事件，降级为普通规则。该条规则的事件数据已经入库
                return rtnEventItem
        else:  # 命中数据为None，说明当前匹配到的是入口点规则
            # 新建EventItem对象
            rtnEventItem = self.EventItem(
                InputData['HoneyID'],
                InputData['Timestamp'],
                InputData['SessionID'],
                InputData['ProcessName'],
                Rule['AttackType'])
        # 新建事件或者命中已有事件，先将行为数据入队，追加数据标记
        eventContentTextLine = self.FlagGenerator(
            InputData, Rule['ContentLine'])  # 根据规则构造数据标记
        rtnEventItem.AppendContentLine(eventContentTextLine)  # 追加事件标记
        # rtnEventItem.EventDataQueue.appendleft(self.CovertToSimple(InputData, eventContentTextLine))  # 数据标记并入队
        InputData['EventMark'] = eventContentTextLine
        rtnEventItem.EventDataQueue.appendleft(InputData)
        if Rule['IsCritical']:
            newEventID = None
            # 入库的事件的Level和AttackType需替换为关键点规则的对应字段内容，覆盖前序规则对应字段的内容
            rtnEventItem.AttackType = Rule['AttackType']
            rtnEventItem.Level = Rule['Level']
            newEventID = self._InsertNewEvent(
                InputData,
                rtnEventItem.Level,
                rtnEventItem.AttackType,
                rtnEventItem.EventContentText)
            rtnEventItem.EventID = newEventID
            self._events[newEventID] = rtnEventItem
            while True:
                try:  # 回溯该事件的行为数据队列
                    # 将数据用新获得的EventID关联，插入event_detail表
                    self._InsertEventDetailData(
                        rtnEventItem.EventDataQueue.pop(), newEventID)
                except IndexError:
                    break

            hitBlackListSet = self._blackList.get(InputData['SessionID'], None)
            if hitBlackListSet == None:
                self._blackList[InputData['SessionID']
                                ] = hitBlackListSet = set()
            hitBlackListSet.add(rtnEventItem)  # 将直接触发事件的进程SessionID和该事件关联起来

            newBlackListKey = ''
            if InputData['DataType'] == 'SampleInfo':
                # 样本落地触发规则，样本文件路径计入黑名单
                newBlackListKey = '%d:%s' % (
                    InputData['HoneyID'], InputData['SampleName'])
            elif InputData['DataType'] == 'ProcInfo' and InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_PROCESS_CREATE:
                # 新建进程行为触发规则，子进程的SessionID将被计入黑名单
                newBlackListKey = '%d#%d#%d' % (
                    InputData['HoneyID'], InputData['OpPID'], InputData['Timestamp'])
            elif InputData['DataType'] == 'FileInfo' and InputData['OpCode'] == NeoHoney_TypeLib.FileInfoOp.FLEM_CREATE_FILE:
                # 新建文件行为触发规则，新文件路径计入黑名单
                newBlackListKey = '%d:%s' % (
                    InputData['HoneyID'], InputData['OpFilePath'])

            if bool(newBlackListKey):
                newBlackListItem = self._blackList.get(newBlackListKey, None)
                if newBlackListItem == None:
                    self._blackList[newBlackListKey] = newBlackListItem = set()
                newBlackListItem.add(rtnEventItem)

        return rtnEventItem

    def __LoopThroughEventItemSet(self, InputSet, InputData, ExcludeEventData = set()):
        '遍历EventItemSet，完成数据入库'
        if type(InputSet) != set:
            raise TypeError("Invaild InputSet type, expecting set().")

        for eventItem in InputSet.difference(ExcludeEventData):
            # 将当前这一轮已经分析入库过的时间ID排除掉，以免相同的数据在同一个事件里入库两次
            self._InsertEventDetailData(InputData, eventItem.EventID)

    def __UpdateBlackList(self, InputKey, InputSet):
        '更新黑名单项。输入Key和set，如果这个Key在_blacklist里已经存在，则将set和目标set项合并，否则添加这个key并指向传入的set'
        if type(InputSet) != set:
            raise TypeError("Invaild InputSet type, expecting set().")
        if InputKey in self._blackList:
            self._blackList[InputKey].update(InputSet)
        else:
            self._blackList[InputKey] = InputSet

    def AnalyseHoneyData(self, InputData):
        '蜜罐数据分析主函数'

        # 对原算法实现进行调整，原算法以文件路径为主要污点关联依据，
        # 调整后的算法将以特定进程实例（SessionID）为主要污点传播依据，
        # 仅保留样本文件以及污点进程创建的新文件的路径和事件的关联

        # 1、以污点传播原理追踪事件。关联到污点（EventItem）的数据将在分析之前先和对应的EventIDs关联
        #   以下数据将会作为污点源，这些路径将和EventItem关联（在_RuleTriggered()内实现）：
        #       触发事件落地的进程SessionID
        #       触发事件落地的样本文件路径
        #       产生样本的进程的SessionID
        #   以下数据将触发污点的传播，这些数据将和污点来源的EventItem关联（在本方法内实现）：
        #       污点进程创建的新文件以及样本文件路径
        #       污点进程创建的新进程的SessionID
        #       读取污点文件（样本）的进程的SessionID
        #       将污点文件路径作为模块加载的进程的SessionID
        #       污点文件被重命名之后，新文件名应继承相同的污点
        #   新算法也不再缓存所有进程的行为数据，只缓存触发非关键规则的进程的行为数据，并在事件落地之后全部出队，新数据根据进程黑名单匹配事件实施追踪
        #   回溯更早的数据请查阅原始数据
        # 2、匹配到污点的数据将在分析之前先写入数据库，并将该进程或者路径标记为污点
        # 3、调用AnalyseMain()分析，用_RuleTriggered()函数获取规则触发

        # 分析之前检查数据是可以匹配已存在的事件（污点），如果可以，污点将发生传播

        keyString = ''
        newKeyString = ''
        # 第一轮检查，涵盖大部分关注行为
        if InputData['DataType'] == 'ProcInfo' and InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_PROCESS_CREATE:
            # 污点进程新建进程，子进程继承父进程的污点
            keyString = InputData['SessionID']
            newKeyString = '%d#%d#%d' % (
                InputData['HoneyID'], InputData['OpPID'], InputData['Timestamp'])
        elif InputData['DataType'] == 'FileInfo' and InputData['OpCode'] == NeoHoney_TypeLib.FileInfoOp.FLEM_CREATE_FILE:
            # 污点进程新建文件，文件本身继承污点
            keyString = InputData['SessionID']
            newKeyString = '%d:%s' % (
                InputData['HoneyID'], InputData['OpFilePath'])
        elif InputData['DataType'] == 'SampleInfo':
            # 新样本落地，样本本身继承产生该样本的进程的污点
            keyString = InputData['SessionID']
            newKeyString = '%d:%s' % (
                InputData['HoneyID'], InputData['SampleName'])
        elif InputData['DataType'] == 'ModuleInfo' and InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_MODULE_LOAD:
            # 进程将污点文件作为模块加载，进程继承污点
            keyString = '%d:%s' % (
                InputData['HoneyID'], InputData['ModulePath'])
            newKeyString = InputData['SessionID']

        hitEventSet1 = self._blackList.get(keyString, set())
        self.__UpdateBlackList(newKeyString, hitEventSet1)

        keyString = ''
        newKeyString = ''
        # 第二轮检查，针对文件和进程
        if InputData['DataType'] == 'ProcInfo' and InputData['OpCode'] == NeoHoney_TypeLib.ProcInfoOp.PRCM_PROCESS_CREATE:
            # 新建进程操作增补检查，检查父进程文件本身是否黑名单
            keyString = '%d:%s' % (
                InputData['HoneyID'], InputData['ProcessName'])
            newKeyString = '%d#%d#%d' % (
                InputData['HoneyID'], InputData['OpPID'], InputData['Timestamp'])
        elif InputData['DataType'] == 'FileInfo':
            # 文件操作增补检查，针对重命名和其他行为
            keyString = '%d:%s' % (
                InputData['HoneyID'], InputData['OpFilePath'])
            if InputData['OpCode'] not in {NeoHoney_TypeLib.FileInfoOp.FLEM_CREATE_FILE, NeoHoney_TypeLib.FileInfoOp.FLEM_RENAME_FILE}:
                # 除打开文件和重命名文件之外其他文件行为，如果进程操作污点文件，进程本身继承污点
                newKeyString = InputData['SessionID']
            elif InputData['OpCode'] == NeoHoney_TypeLib.FileInfoOp.FLEM_RENAME_FILE:
                # 污点文件被重命名，新文件名继承污点
                newKeyString = '%d:%s' % (
                    InputData['HoneyID'], NeoHoney_TypeLib._WChar2String(InputData['OpData']))

        hitEventSet2 = self._blackList.get(keyString, set())
        self.__UpdateBlackList(newKeyString, hitEventSet2)

        hitItems = self.AnalyseMain(InputData, self._RuleTriggered, self._rules)
        self.__LoopThroughEventItemSet(hitEventSet1 | hitEventSet2, InputData, hitItems)