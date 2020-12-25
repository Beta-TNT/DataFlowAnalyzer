'时序分析算法基础模块,实现最基础的业务无关的时序分析逻辑'

__author__ = 'Beta-TNT'
__version__= '2.6.0'

import re, os, base64
from enum import IntEnum
from abc import ABCMeta, abstractmethod

class AnalyseBase(object):
    '时序分析算法核心类'

    '''规则字段结构（字典）：
    Operator    ：字段匹配运算，见OperatorCode
    PrevFlag    ：时序分析算法历史匹配Flag构造模板，为空则是入口点规则
    RemoveFlag  ：字段匹配规则和历史匹配Flag命中之后，需要删除的Flag。Flag不存在不会触发异常
    CurrentFlag ：时序分析算法本级规则命中后构造Flag的模板
    PluginNames ：需要调用的插件名列表，请将插件名列表以分号分隔写入这个字段，引擎将按列表顺序以串行执行运行插件函数。原PluginName字段废除
    FieldCheckList[]    ：字段匹配项列表
        字段匹配项结构（字典）：
        FieldName   ：要进行匹配的字段名
        MatchContent：匹配内容
        MatchCode   ：匹配方式代码
    '''
    # Lifetime, Threshold和Expire功能拆分成单独的插件，基础算法中不再实现

    class OperatorCode(IntEnum):
        Preserve = 0 # 预留
        OpAnd = 1
        OpOr = 2
        # 逻辑代码对应的负数代表结果取反，例如-1代表NotAnd，不再显式声明


    class MatchMode(IntEnum):
        Preserve = 0 # 为带字段比较功能插件预留
        Equal = 1  # 值等匹配。数字相等或者字符串完全一样
        TextMatching = 2  # 文本匹配，忽略大小写
        RegexMatching = 3  # 正则匹配
        GreaterThan = 4  # 大于（数字）
        LengthEqual = 5 # 元数据比较：数据长度等于（忽略数字类型数据）
        LengthGreaterThan = 6 # 元数据比较：数据长度大于（忽略数字类型数据）
        # 匹配代码对应的负数代表结果取反，例如-1代表不等于（NotEqual），不再显式声明

        # 原本考虑加入翻转比较运算（Reverse），交换比较运算的左值和右值，但考虑之后发现不具备实际意义：
        # 1、翻转比较不影响相等比较的结果；
        # 2、翻转比较用于多结果文本匹配的时候，完全可以用OpOr运算符并列多次比较代替；
        # 3、翻转比较用于正则匹配（将输入数据而非规则作为正则表达式）时会导致完全无法预料的结果；
        # 4、翻转比较用于数字大于比较的时候，和小于等于运算等价，可以用-4代替；
        # 5、翻转比较无法用于元数据比较
        # 综上，对于所有比较运算，翻转比较都不具备实际意义或者可用已有方式代替，因此不将其加入功能
        # 翻转比较已通过插件实现，如有必要可通过插件调用
        
    class PluginBase(object):
        '分析插件基类'
        # 原插件功能设计逻辑：在派生类里作为规则命中之后执行的业务函数插入分析逻辑最后一步。
        # 原插件用户函数传入数据项：已通过字段匹配以及Flag匹配的单条数据，命中的规则
        # 原插件用户函数返回值：数据是否满足插件分析逻辑/Boolean
        # 新插件预期功能：代替原分析算法逻辑里的SingleRuleTest()函数，并且可以自由调用原函数，以及在该函数逻辑前后追加其他处理代码

        _ExtraRuleFields = {}
        _AnalyseBase = None # 插件实例化时需要分析算法对象实例

        def __init__(self, AnalyseBaseObj):
            if not AnalyseBaseObj or AnalyseBase not in {type(AnalyseBaseObj), type(AnalyseBaseObj).__base__}:
                raise TypeError("invalid AnalyseBaseObj Type, expecting AnalyseBase.")
            else:
                self._AnalyseBase = AnalyseBaseObj # 构造函数需要传入分析算法对象实例

        def _DefaultAnalyseSingleData(self, InputData, InputRule):
            return self._AnalyseBase._DefaultSingleRuleTest(InputData, InputRule)

        def AnalyseSingleData(self, InputData, InputRule):
            '插件数据分析方法用户函数，接收被分析的dict()类型数据和规则作为参考数据，由用户函数判定是否满足规则。返回值定义同_DefaultSingleRuleTest()函数'
            # 可以在分析数据之前对数据进行处理，比如编码转换或者格式化字符串等
            # 如果没有特殊处理，也可以直接调用原分析逻辑的单条数据分析函数
            # 如果需要对原分析逻辑处理结果进行进行再处理，可以这样：

            # （数据预处理或者功能扩展）
            # rtn = self._AnalyseBase._DefaultSingleRuleTest(InputData, InputRule)
            # (对rtn进行再处理或者其他功能扩展)
            # return rtn

            # 特别注明，如果需要调用原分析逻辑里的单规则分析函数，
            # 必须是_DefaultSingleRuleTest()，而非SingleRuleTest()
            # 否则由于SingleRuleTest()里也会调用插件的AnalyseSingleData()函数，会形成无限递归

            # 当前版本的分析插件用户函数仅作为分析逻辑里SingleRuleTest()函数的代用品
            # 如果需要实现之前后置型分析插件用户函数，请在派生类里实现

            # 该方法不做抽象方法，如果插件无需实现这部分分析逻辑，可不重写AnalyseSingleData()函数，默认执行原分析逻辑的单规则匹配函数
            return self._DefaultAnalyseSingleData(InputData, InputRule)

        @property
        def PluginInstructions(self):
            '插件介绍文字'
            pass

        @property
        def ExtraRuleFields(self):
            '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
            return self._ExtraRuleFields

    _flags = dict() # Flag-缓存对象字典
    _plugins = dict() # 插件名-插件对象实例字典
    _pluginExtraRuleFields = dict() # 插件专属规则字段名-插件对象字典，暂无实际应用

    PluginDir = os.path.abspath(os.path.dirname(__file__)) + '/plugins/' # 插件存放路径

    def __init__(self):
        self.__LoadPlugins('AnalysePlugin')

    def __getPlugin(self):
        return filter(
            lambda str:(True, False)[str[-4:] == '.pyc' or str.find('__init__.py') != -1],
            os.listdir(self.PluginDir)
        )

    def __LoadPlugins(self, PluginInterfaceName):
        '加载插件，返回包含所有有效插件实例的dict()，key是插件名，value是插件对象的实例'
        if os.path.isdir(self.PluginDir):
            self._plugins.clear()
            print("Loading plugin(s)...")
            for plugin in self.__getPlugin():
                try:
                    pluginName = os.path.splitext(plugin)[0]
                    self._plugins[pluginName] = getattr(
                        __import__(
                            "plugins.{0}".format(pluginName),
                            fromlist = [pluginName]
                        ),
                        PluginInterfaceName
                    )(self)
                    print(pluginName)
                except Exception:
                    continue
            print("{0} plugin(s) loaded.".format(len(self._plugins)))


    def RemoveFlag(self, InputFlag):
        '尝试移除指定的Flag'
        self._flags.pop(InputFlag, None)

    @staticmethod
    def _DefaultFieldCheck(TargetData, InputFieldCheckRule):
        '默认的字段检查函数，输入字段的内容以及单条字段检查规则，返回True/False'
        if type(InputFieldCheckRule) != dict:
            raise TypeError("Invalid InputFieldCheckRule type, expecting dict")
        fieldCheckResult = False
        matchContent = InputFieldCheckRule["MatchContent"]
        matchCode = InputFieldCheckRule["MatchCode"]
        if matchCode == AnalyseBase.MatchMode.Preserve:
            pass
        elif abs(matchCode) == AnalyseBase.MatchMode.Equal:
            # 相等匹配 equal test
            try:
                if type(TargetData) in {bytes, bytearray}:
                    # 如果原数据类型是二进制，则试着将比较内容字符串按BASE64转换成bytes后再进行比较
                    matchContent = base64.b64decode(matchContent)
                if type(matchContent) == type(TargetData):  # 同数据类型，直接判断
                    fieldCheckResult = (matchContent == TargetData)
                else:  # 不同数据类型，都转换成字符串判断
                    fieldCheckResult = (str(matchContent) == str(TargetData))
            except:
                pass
        elif abs(matchCode) == AnalyseBase.MatchMode.TextMatching:
            # 文本匹配（字符串） text matching (ignore case)
            try:
                if type(TargetData) in {bytes, bytearray}:
                    # 如果原数据类型是二进制，则试着将比较内容字符串按BASE64转换成bytes后再进行比较
                    matchContent = base64.b64decode(matchContent)
                else:
                    matchContent = str(matchContent) if type(matchContent) != str else matchContent
                    TargetData = str(TargetData) if type(TargetData) != str else TargetData
                fieldCheckResult = (matchContent in TargetData)
            except:
                pass
        elif abs(matchCode) == AnalyseBase.MatchMode.RegexMatching:
            # 正则匹配（字符串） regex match
            if type(matchContent) != str:
                matchContent = str(matchContent)
            if type(TargetData) != str:
                TargetData = str(TargetData)
            fieldCheckResult = bool(re.match(matchContent, TargetData))
        elif abs(matchCode) == AnalyseBase.MatchMode.GreaterThan:
            # 大小比较（数字，字符串尝试转换成数字，转换不成功略过该字段匹配）
            if type(matchContent) in (int, float) and type(TargetData) in (int, float):
                fieldCheckResult = (matchContent > TargetData)
            else:
                try:
                    fieldCheckResult = (int(matchContent) > int(TargetData))
                except:
                    pass
        elif abs(matchCode) == AnalyseBase.MatchMode.LengthEqual:
            # 元数据比较：数据长度相等。忽略无法比较长度的数字类型
            if type(matchContent) not in (int, float, bool, complex):
                try:
                    fieldCheckResult = (len(matchContent) == int(TargetData))
                except:
                    pass
            else:
                pass
        elif abs(matchCode) == AnalyseBase.MatchMode.LengthGreaterThan:
            # 元数据比较：数据长度大于。忽略无法比较长度的数字类型
            if type(matchContent) not in (int, float, bool, complex):
                try:
                    fieldCheckResult = (len(matchContent) > int(TargetData))
                except:
                    pass
            else:
                pass
        else:
            pass
        fieldCheckResult = ((matchCode < 0) ^ fieldCheckResult) # 负数代码，结果取反
        return fieldCheckResult

    @staticmethod
    def _DefaultFlagGenerator(InputData, InputTemplate, BytesDecoding='utf-16'):
        '默认的Flag生成函数，根据输入的数据和模板构造Flag。将模板里用大括号包起来的字段名替换为InputData对应字段的内容，如果包含bytes字段，需要指定解码方法'
        #Default flag generator, replaces the placeholder substrings in InputTemplate like '{key}' with the value of InputData['key'].
        #Bytes type will be decoded into str with given decoding.
        if not InputTemplate:
            return None

        if type(InputTemplate) != str:
            raise TypeError("Invalid Template type, expecting str")
        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, expecting dict")
            
        for inputDataKey in InputData:
            inputDataItem = InputData[inputDataKey]
            if type(inputDataItem) in (bytes, bytearray):
                try:
                    InputData[inputDataKey] = inputDataItem.decode(BytesDecoding)
                except Exception:
                    InputData[inputDataKey] = ""

        rtn = InputTemplate.format(**InputData)
        return rtn

    def _DefaultSingleRuleTest(self, InputData, InputRule):
        '用数据匹配单条规则，如果数据匹配当前则，返回Flag命中的应用层数据对象'
        # Single rule test function. Returns a tuple like (True, HitCacheItem) if the the data hit the rule,
        # or (False, None) if the data hits nothing.
        # 20201222 修改
        # Before：返回(命中与否，命中的CacheItem)
        # After：返回命中的用户数据项（原CacheItem.ExtraItem）
        if type(InputData) != dict or type(InputRule) != dict:
            raise TypeError("Invalid InputData or InputRule type, expecting dict")

        fieldCheckResult = False
        if type(InputRule["FieldCheckList"]) in (dict, list) and bool(InputRule["FieldCheckList"]):
            fieldCheckResults = list(
                map(
                    lambda y:AnalyseBase.FieldCheck(InputData[y['FieldName']], y),
                    filter(
                        lambda x:x.get('FieldName') in InputData,
                        InputRule["FieldCheckList"]
                    )
                )
            )
            if abs(InputRule["Operator"]) == AnalyseBase.OperatorCode.OpOr:
                fieldCheckResult = any(fieldCheckResults)
            elif abs(InputRule["Operator"]) == AnalyseBase.OperatorCode.OpAnd:
                fieldCheckResult = all(fieldCheckResults)
            # 负数匹配代码结果取反，而且如果字段匹配结果列表为空，说明字段匹配规则全部失配，这条规则就不是给这个数据的
            fieldCheckResult = bool(fieldCheckResults) and ((InputRule["Operator"] < 0) ^ fieldCheckResult) 
        else:
            # 字段匹配列表为空，直接判定字段匹配通过
            # Field check is None, ignore it.
            fieldCheckResult = True

        if not fieldCheckResult:
            return (False, None)

        if bool(InputRule["PrevFlag"]):  # 判断前序flag是否为空
            # 检查Flag缓存，如果成功，返回一个包含两个元素的Tuple，分别是命中结果（True/False）和命中的CacheItem对象
            # Prevflag check succeed, return (True, Hit CacheItem)

            # 20201218修改本函数返回值定义
            # Before：返回CacheItem
            # After：返回业务层定义数据（原CacheItem.ExtraData）
            currentFlag = self.FlagGenerator(InputData, InputRule["PrevFlag"])
            rtn, hitItem = currentFlag in self._flags, self._flags.get(currentFlag)
            return rtn, hitItem
        else:
            # 前序flag为空，入口点规则，Flag匹配过程直接命中，命中的CacheItem对象为None
            # Prevflag is '' or None, it means this is a init rule. Return (True, None)
            return (True, None)

    def _DefaultClearCache(self):
        '默认的清除缓存函数，将_flags字典清空'
        self._flags.clear()

    @staticmethod
    def FieldCheck(TargetData, InputFieldCheckRule):
        '字段检查函数，可根据需要在派生类里重写。'
        return AnalyseBase._DefaultFieldCheck(TargetData, InputFieldCheckRule)

    # 20201222 修改
    # 不再基础算法里实现Flag生存期管理，弃用FlagCheck函数，直接操作_flags完成Flag检查
    # def FlagCheck(self, InputFlag):
    #     'Flag检查函数，可根据需要在派生类里重写。应返回一个二元Tuple，分别是Flag是否有效，以及有效的Flag命中的对象。没有命中返回(False, None)'
    #     return self._DefaultFlagCheck(InputFlag)

    @staticmethod
    def FlagGenerator(InputData, InputTemplate):
        'Flag生成函数，可根据需要在派生类里重写'
        'Flag Generator func, you may overwrite it in child class if necessary.'
        return AnalyseBase._DefaultFlagGenerator(InputData, InputTemplate)

    def SingleRuleTest(self, InputData, InputRule):
        '单规则匹配函数，可根据需要在派生类里重写。本函数也是分析插件的入口位置'
        'Single rule test func, you may overwrite it in child class if necessary.'
        # 插件入口做在这里。如果规则包含有效的插件名，则执行插件分析逻辑，否则执行默认分析逻辑
        # 因此，如果需要在插件功能执行的同时还需要默认分析逻辑，请在插件代码中调用
        # 已实现多插件调用支持，PluginNames字段代替原PluginName字段，需要调用的多个插件名称按调用顺序以分号;分隔
        # 如果只需要调用一个插件，可以只写一个插件名，功能和原版本相同
        pluginNameList = list(filter(None, map(lambda str:str.strip(), InputRule.get('PluginNames','').split(';'))))
        if pluginNameList:
            pluginResults = set()
            i = 0
            while True:
                if i>= len(pluginNameList):
                    break
                pluginObj = self._plugins.get(pluginNameList[i])
                if pluginObj:
                    pluginResult = pluginObj.AnalyseSingleData(InputData, InputRule)
                    pluginResults.add(pluginResult)
                    if not pluginResult[0]:
                        # 按列表次序执行插件程序，并且在第一个返回失配结果的配件结束轮询
                        # 串行方式用于让一条规则以插件列表顺序，按AND逻辑应用多个插件功能，
                        # 比如将生存时间插件和限定命中次数插件结合起来
                        # 实现如“一秒内收到同来源IP地址连接多少次数即触发”这样的复合条件规则
                        # 也可以实现通过编码转换插件对数据进行预处理
                        break
                i+= 1
            # 如果所有插件都返回了相同的返回值，即将该返回值作为最终的返回值，否则返回False, None
            return (False, None) if len(pluginResults) != 1 else pluginResults.pop()
        else:
            return self._DefaultSingleRuleTest(InputData, InputRule)

    def PluginExec(self, PluginName, InputData, InputRule):
        '单独的插件执行函数，如果传入的插件名无效，返回(False, None)'
        # 该方法的应用场景是一个插件调用另一个插件的情况。
        # 如果用无效的插件名调用本函数，会抛出异常。
        # 因此需要由父级插件调用_plugins()属性检查调用的子插件是否存在或者捕获异常
        PluginObj = self._plugins.get(PluginName)
        if PluginObj:
            return PluginObj.AnalyseSingleData(InputData, InputRule)
        else:
            return (False, None)
            # raise Exception("Plugin '%s' not found." % PluginName)

    def ClearCache(self):
        '清除缓存方法，重置缓存状态。可根据需要在派生类里重写'
        self._DefaultClearCache()

    def AnalyseMain(self, InputData, ActionFunc, InputRules):
        return self._DefaultAnalyseMain(InputData, ActionFunc, InputRules)
    
    def _DummyActionFunc(self, InputData, rule, hitItem, currentFlag):
        import uuid
        return str(uuid.uuid1())


    def _DefaultAnalyseMain(self, InputData, ActionFunc, InputRules):
        '''默认的分析算法主函数。根据已经加载的规则和输入数据。
        基础分析算法判断是否匹配分为字段匹配和Flag匹配两部分，只有都匹配成功才算该条数据匹配成功。
        ActionFunc传入一个函数，该函数需要接收命中规则的数据inputData（dict）、对应命中的规则rule（dict）、命中的缓存对象hitItem(Obj)，生成的CurrentFlag（obj）作为参数,
        如果输入数据匹配成功，数据调用传入的ActionFunction()作为输出接口，并返回一个用户自定义数据对象。
        每成功匹配一条规则，传入的ActionFunc()将被执行一次
        返回值是set()类型，包含了该条数据命中的所有用户自定义数据对象。如果没有命中返回长度为0的空集合（不是None）
        由于提供了单条规则匹配的方法，用户也可参考本函数自行实现分析函数

        Main function. Analyzing key-value based data (dict) with given rule set.
        Each time the input data hits a rule, ActionFunc() will be called once and return a user-defined data object, use this as an output interface.
        Return a set() which includes all the user-defined data object that input data hits, return an empty set if input data hits nothing (not None).
        '''
        if InputRules == None:
            return None

        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, expecting dict()")
        
        if not ActionFunc:
            ActionFunc = self._DummyActionFunc
            
        rtn = set()  # 该条数据命中的缓存对象集合

        for rule in InputRules:  # 规则遍历主循环
            # 遍历检查单条规则
            # Tests every single rule on input data
            # 如果规则包含插件调用，将在单规则检查函数SingleRuleTest()中被调用
            ruleCheckResult, hitItem = self.SingleRuleTest(InputData, rule)
            # 20201218 修改
            # Before：SingleRuleTest返回CacheItem
            # After：SingleRuleTest返回ExtraData
            # CacheItem的功能是对Flag实施声明周期管理，实际上是算法基类的内部数据对象，原则上不应直接提供给业务层
            # 何况目前本算法唯一的上层应用也没有用到CacheItem的相关功能
            # 20201222 修改
            # 将Threshold、Lifetime和Expire功能拆分成单独的插件，基础算法不再实现该功能

            if ruleCheckResult:  # 字段匹配和前序Flag匹配均命中（包括前序Flag为空的情况），规则命中
                # 1、构造本级Flag；   Generate current flag;
                # 2、调用ActionFunc()获得用户数据，构造CacheItem对象；  Call ActionFunc() to get a user defined data
                # 3、以本级Flag作为Key，新的CacheItem作为Value，存入self._flags[]； Save cache item into self._flags[], with current flag as key
                currentFlag = self.FlagGenerator(InputData, rule.get("CurrentFlag"))
                removeFlag = self.FlagGenerator(InputData, rule.get("RemoveFlag"))
                
                # 将命中规则的数据、规则本身、命中的缓存对象以及命中的Flag传给用户函数，获得用户函数返回值
                newDataItem = ActionFunc(InputData, rule, hitItem, currentFlag)
                if currentFlag and currentFlag not in self._flags:
                    # 如果是入口点规则，命中的缓存对象是None，用户函数可据此判断
                    self.RemoveFlag(removeFlag)
                    # Passing the key data, hit rule itself, hit cache item (None if the data hits a init rule) and flag to ActionFunc()
                    if newDataItem:  # 用户层还可以再做一次判断，如果用户认为已经满足字段匹配和前序FLAG匹配的数据仍不符合分析条件，可返回None，缓存数据将不会被记录
                        # 20201222修改
                        # 返回值由CacheItem改为业务层ActionFunc()函数的返回值
                        # 原Flag的Threshold和Lifetime功能拆分成插件实现
                        self._flags[currentFlag] = newDataItem
                        rtn.add(newDataItem)
                        # 20201222修改
                        # Expire和Delay功能单独拆分成插件
                else:
                    # Flag冲突
                    # 忽略
                    pass
        return rtn