'时序分析算法基础模块,实现最基础的业务无关的时序分析逻辑'

__author__ = 'Beta-TNT'

import re, os
import threading
from enum import IntEnum
from abc import ABCMeta, abstractmethod
from imp import find_module, load_module

class AnalyseBase(object):
    '时序分析算法核心类'

    '''规则字段结构（字典）：
    Operator    ：字段匹配运算，见OperatorCode
    PrevFlag    ：时序分析算法历史匹配Flag构造模板，为空则是入口点规则
    CurrentFlag ：时序分析算法本级规则命中后构造Flag的模板
    FlagThrehold：本级规则构造的Flag触发门槛。相同的Flag每次命中消耗1，消耗到0才能真正触发；默认0则不存在门槛，直接触发
    FlagLifetime：本级规则构造的Flag生存期。Flag被真正触发之后，相同的Flag再次触发会消耗1，消耗到0后Flag删除
    Expire      ：当前规则触发生成的Flag的生存时间，单位是秒，浮点数。如该项不存或0，则表示生存时间为无限
    PluginName  ：需要调用的插件名
    FieldCheckList[]    ：字段匹配项列表
        字段匹配项结构（字典）：
        FieldName   ：要进行匹配的字段名
        MatchContent：匹配内容
        MatchCode   ：匹配方式代码

    缓存对象CacheItem（命中后存储的Flag对应的数据）：
    Threhold    ：  门槛消耗剩余，来自触发这条规则的FlagThrehold字段。
                    Flag生成之后每次命中Threhold消耗1，直到Threhold变为0时这个Flag才能正式生效。
                    Flag判定时应判断Threhold是否为0，Threhold为0的Flag才是生效的Flag，否则将Flag的Threhold减1，并返回Flag未命中
    Lifetime    ：  生存期剩余，来自触发这条规则的FlagLifetime字段。
                    Flag生效之后（Threhold消耗完）每次命中Lifetime消耗1。
                    当最后一次命中之后Lifetime减0时这个Flag将被销毁。
                    Lifetime如果初始就是0，则为永久有效，跳过Lifetime判定和消耗流程。
    ExtraData   ：  附加数据，可存储业务需要的任何数据。
    FlagContent ：  对应Flag的内容
    '''


    class OperatorCode(IntEnum):
        OpOr = 0
        OpAnd = 1
        OpNotOr = 2
        OpNotAnd = 3


    class MatchMode(IntEnum):
        none = 0

        Equal = 1  # 值等匹配。数字相等或者字符串完全一样
        TextMatching = 2  # 文本匹配，忽略大小写
        RegexMatching = 3  # 正则匹配
        GreaterThan = 4  # 大于（数字）

        # 负数为对应匹配方式的结果取反
        NotEqual = -1
        ReverseTextMatching = -2
        ReverseRegexMatching = -3
        LessThan = -4
        
    class PluginBase(object):
        '插件基类'
        # 原插件功能设计逻辑：在派生类里作为规则命中之后执行的业务函数插入分析逻辑最后一步。
        # 原插件用户函数传入数据项：已通过字段匹配以及Flag匹配的单条数据，命中的规则
        # 原插件用户函数返回值：数据是否满足插件分析逻辑/Boolean
        # 新插件预期功能：代替原分析算法逻辑里的SingleRuleTest()函数，并且可以自由调用原函数，以及在该函数逻辑前后追加其他处理代码

        _ExtraRuleFields = {}
        _AnalyseBase = None # 插件实例化时需要分析算法对象实例

        def __init__(self, AnalyseBaseObj):
            if not (type(AnalyseBaseObj) == AnalyseBase or type(AnalyseBaseObj).__base__ == AnalyseBase):
                raise TypeError("Invaild AnalyseBaseObj Type, expecting AnalyseBase.")
            self._AnalyseBase = AnalyseBaseObj # 构造函数需要传入分析算法对象实例

        def _DefaultAnalyseSingleData(self, InputData, InputRule):
            return self._AnalyseBase._DefaultSingleRuleTest(InputData, InputRule)

        def AnalyseSinlgeData(self, InputData, InputRule):
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
            # 否则由于SingleRuleTest()里也会调用插件的AnalyseSinlgeData()函数，会形成无限递归

            # 当前版本的分析插件用户函数仅作为分析逻辑里SingleRuleTest()函数的代用品
            # 如果需要实现之前后置型分析插件用户函数，请在派生类里实现

            # 该方法不做抽象方法，如果插件无需实现这部分分析逻辑，可不重写AnalyseSinlgeData()函数，默认执行原分析逻辑的单规则匹配函数
            return self._DefaultAnalyseSingleData(InputData, InputRule)

        @property
        def PluginInstructions(self):
            '插件介绍文字'
            pass

        @property
        def ExtraRuleFields(self):
            '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
            return self._ExtraRuleFields

    class CacheItem(object):
        '算法缓存对象'

        _Threhold = 0  # 门槛剩余
        _LifeTime = 0  # 生存期剩余
        _FlagContent = ''  # Flag内容
        _ExtraData = None  # 附加数据
        _Valid = True  # 指示当前Flag是否应还有效，当生存期消耗完毕或者超过有效时间时为False，其他情况包括门槛未消耗完毕时仍然为True。
        # 检查缓存对象是否可用应使用Check()函数，而不是直接使用_Valid属性

        @property
        def ExtraData(self):
            return self._ExtraData

        @property
        def ThreholdRemain(self):
            return self._Threhold

        @property
        def LifetimeRemain(self):
            return self._LifeTime

        @property
        def FlagContent(self):
            return self._FlagContent

        @property
        def Valid(self):
            return self._Valid

        def __init__(self, FlagContent, Threhold, LifeTime, ExtraData):
            self._Threhold = Threhold
            self._LifeTime = LifeTime
            self._FlagContent = FlagContent
            self._ExtraData = ExtraData

        def _ConsumeThrehold(self):
            '消耗门槛操作，如果门槛已经消耗完毕，返回True。在门槛消耗完毕之前，Valid属性仍然是True'
            if self._Valid == False:
                return False

            if self._Threhold <= 0:
                return True
            else:
                self._Threhold -= 1
                return False

        def _ConsumeLifetime(self):
            '消耗生存期操作。如果还在生存期内或者生存期无限（值为0）返回True，否则返回false并将Valid属性设为False'
            if self._Valid == False:
                return False

            if self._LifeTime == 0:
                return True
            else:
                self._LifeTime -= 1
                # 生存期失效之前最后一次调用，返回True并将_Valid设为False
                self._Valid = not (self._LifeTime == 0)
                return True

        def Check(self):
            return self._DefaultCheck()

        def _DefaultCheck(self):  # 检查是否有效
            if not self._Valid:
                return False
            else:
                if self._ConsumeThrehold():
                    return self._ConsumeLifetime()
                else:
                    return False

    _cache = dict() # Flag-缓存对象字典
    _timer = dict() # Flag-计时器对象字典
    _plugins = dict() # 插件名-插件对象实例字典

    PluginDir = os.path.abspath(os.path.dirname(__file__)) + '/plugins/' # 插件存放路径

    def __init__(self):
        self.__LoadPlugins('AnalysePlugin')

    def __getPlugin(self): 
        plugins = os.listdir(self.PluginDir)
        fil = lambda str: (True, False)[str[-4:] == '.pyc' or str.find('__init__.py') != -1]
        return filter(fil, plugins)

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


    def __RemoveFlag(self, InputFlag):
        if InputFlag in self._cache:
            self._cache.pop(InputFlag)
        if InputFlag in self._timer:
            self._timer.pop(InputFlag)

    def _DefaultFlagPeek(self, InputFlag):
        '默认Flag偷窥函数，检查Flag是否有效。返回定义和默认Flag检查函数相同，但并不会触发Threhold或Lifetime消耗，也不进行缓存管理。对于Threhold不为0的Flag也返回缓存对象'
        rtn = False
        hitItem = self._cache.get(InputFlag, None)
        if hitItem:
            rtn = hitItem.Valid
        return rtn, hitItem

    def _DefaultFlagCheck(self, InputFlag):
        '默认Flag检查函数，检查Flag是否有效。返回一个Tuple，包括该Flag是否有效(Bool)，以及该Flag命中的缓存对象。如无命中返回(False, None)。检查将完成Flag管理功能'
        rtn, hitItem = self._DefaultFlagPeek(InputFlag)
        if not rtn:
            return False, None
        else:
            rtn = hitItem.Check()
            if not hitItem.Valid:  # 删除过期/无效的Flag（CacheItem）
                self._cache.pop(InputFlag)
            hitItem = None if not rtn else hitItem
            return rtn, hitItem
    
    @staticmethod
    def _DefaultFieldCheck(TargetData, InputFieldCheckRule):
        '默认的字段检查函数，输入字段的内容以及单条字段检查规则，返回True/False'
        if type(InputFieldCheckRule) != dict:
            raise TypeError("Invalid InputFieldCheckRule type, expecting dict")
        fieldCheckResult = False
        MatchContent = InputFieldCheckRule["MatchContent"]
        if InputFieldCheckRule["MatchCode"] in {AnalyseBase.MatchMode.Equal, AnalyseBase.MatchMode.NotEqual}:
            # 相等匹配 equal test
            if type(MatchContent) == type(TargetData):  # 同数据类型，直接判断
                fieldCheckResult = (MatchContent == TargetData)
            else:  # 不同数据类型，都转换成字符串判断
                fieldCheckResult = (str(MatchContent) == str(TargetData))
        elif InputFieldCheckRule["MatchCode"] in {AnalyseBase.MatchMode.TextMatching, AnalyseBase.MatchMode.ReverseTextMatching}:
            # 文本匹配（字符串） text matching (ignore case)
            if type(MatchContent) != str:
                MatchContent = str(MatchContent)
            if type(TargetData) != str:
                TargetData = str(TargetData)
            fieldCheckResult = (TargetData.lower().find(MatchContent.lower()) != -1)
        elif InputFieldCheckRule["MatchCode"] in {AnalyseBase.MatchMode.RegexMatching, AnalyseBase.MatchMode.ReverseRegexMatching}:
            # 正则匹配（字符串） regex match
            if type(MatchContent) != str:
                MatchContent = str(MatchContent)
            if type(TargetData) != str:
                TargetData = str(TargetData)
            fieldCheckResult = (re.match(MatchContent, TargetData) != None)
        elif InputFieldCheckRule["MatchCode"] in {AnalyseBase.MatchMode.GreaterThan, AnalyseBase.MatchMode.LessThan}:
            # 大小比较（数字，字符串尝试转换成数字，转换不成功略过该字段匹配）
            if type(MatchContent) in {int, float} and type(TargetData) in {int, float}:
                fieldCheckResult = (MatchContent > TargetData)
            else:
                try:
                    fieldCheckResult = (int(MatchContent) > int(TargetData))
                except Exception:
                    pass
        if InputFieldCheckRule["MatchCode"] < 0:  # 负数代码，结果取反
            fieldCheckResult = not fieldCheckResult
        return fieldCheckResult

    @staticmethod
    def _DefaultFlagGenerator(InputData, InputTemplate, BytesDecoding='utf-16'):
        '默认的Flag生成函数，根据输入的数据和模板构造Flag。将模板里用大括号包起来的字段名替换为InputData对应字段的内容，如果包含bytes字段，需要指定解码方法'
        #Default flag generator, replaces the placeholder substrings in InputTemplate like '{key}' with the value of InputData['key'].
        #Bytes type will be decoded into str with given decoding.
        if InputTemplate == None:
            return None

        if type(InputTemplate) != str:
            raise TypeError("Invalid Template type, expecting str")
        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, expecting dict")
            
        for inputDataKey in InputData:
            inputDataItem = InputData[inputDataKey]
            if type(inputDataItem) == bytes:
                try:
                    InputData[inputDataKey] = inputDataItem.decode(BytesDecoding)
                except Exception:
                    InputData[inputDataKey] = ""

        rtn = InputTemplate.format(**InputData)
        return rtn

    def _DefaultSingleRuleTest(self, InputData, InputRule):
        '用数据匹配单条规则，如果数据匹配当前则，返回(True, 命中的缓存对象)，否则返回(False, None)'
        # Single rule test function. Returns a tuple like (True, HitCacheItem) if the the data hit the rule,
        # or (False, None) if the data hits nothing.
        if type(InputData) != dict or type(InputRule) != dict:
            raise TypeError("Invalid InputData or InputRule type, expecting dict")

        fieldCheckResult = False
        if '__iter__' in dir(InputRule["FieldCheckList"]):# FieldCheckList must be an iterable

            fieldCheckResults = map(
                lambda y:AnalyseBase.FieldCheck(InputData, y),
                filter(
                    lambda x:x.get('FieldName') in InputData,
                    InputRule["FieldCheckList"]
                )
            )
            if InputRule["Operator"] in {AnalyseBase.OperatorCode.OpOr, AnalyseBase.OperatorCode.OpNotOr}:
                fieldCheckResult = any(fieldCheckResults)
            elif InputRule["Operator"] in {AnalyseBase.OperatorCode.OpAnd, AnalyseBase.OperatorCode.OpNotAnd}:
                fieldCheckResult = all(fieldCheckResults)

            if InputRule["Operator"] in {AnalyseBase.OperatorCode.OpNotOr, AnalyseBase.OperatorCode.OpNotAnd}:
                fieldCheckResult = not fieldCheckResult

            # for fieldChecker in InputRule["FieldCheckList"]:
            #     if fieldChecker.get("FieldName") in InputData:
            #         fieldCheckResult = AnalyseBase.FieldCheck(InputData.get(fieldChecker["FieldName"]), fieldChecker)

            #     if InputRule["Operator"] in {AnalyseBase.OperatorCode.OpOr, AnalyseBase.OperatorCode.OpNotOr} and fieldCheckResult or \
            #             InputRule["Operator"] in {AnalyseBase.OperatorCode.OpAnd, AnalyseBase.OperatorCode.OpNotAnd} and not fieldCheckResult:
            #         # Or/NotOr，  第一个True结果即可结束字段判断
            #         # And/NotAnd，第一个False结果即可结束字段判断
            #         # Field value tests would be ended at first true result on Or/NotOr, or first false result on And/NotAnd,
            #         # the rest tests would be abanboned.
            #         break
            
            # if InputRule["Operator"] in {AnalyseBase.OperatorCode.OpNotAnd, AnalyseBase.OperatorCode.OpNotOr}:
            #     fieldCheckResult = not fieldCheckResult
        else:
            # 字段匹配列表为空，直接判定字段匹配通过
            # Field check is None, ignore it.
            fieldCheckResult = True

        if not fieldCheckResult:
            return (False, None)

        if bool(InputRule["PrevFlag"]):  # 判断前序flag是否为空
            # 检查Flag缓存，如果成功，返回一个包含两个元素的Tuple，分别是命中结果（True/False）和命中的CacheItem对象
            # Prevflag check succeed, return (True, Hit CacheItem)
            return self.FlagCheck(self.FlagGenerator(InputData, InputRule["PrevFlag"]))
        else:
            # 前序flag为空，入口点规则，Flag匹配过程直接命中，命中的CacheItem对象为None
            # Prevflag is '' or None, it means this is a init rule. Return (True, None)
            return (True, None)

    def _DefaultClearCache(self):
        '默认的清除缓存函数，将_cache和_timer两个字典清空'
        self._cache.clear()
        self._timer.clear()

    @staticmethod
    def FieldCheck(TargetData, InputFieldCheckRule):
        '字段检查函数，可根据需要在派生类里重写。'
        return AnalyseBase._DefaultFieldCheck(TargetData, InputFieldCheckRule)

    def FlagCheck(self, InputFlag):
        'Flag检查函数，可根据需要在派生类里重写。应返回一个二元Tuple，分别是Flag是否有效，以及有效的Flag命中的对象。没有命中返回(False, None)'
        return self._DefaultFlagCheck(InputFlag)

    def FlagPeek(self, InputFlag):
        'Flag偷看函数，可根据需要在派生类里重写。返回值定义和FlagCheck相同，但并不会消耗Threhold或Lifetime，也不进行缓存管理'
        return self._DefaultFlagPeek(InputFlag)

    @staticmethod
    def FlagGenerator(InputData, InputTemplate):
        'Flag生成函数，可根据需要在派生类里重写'
        'Flag Generator func, you may overwrite it in child class if necessary.'
        return AnalyseBase._DefaultFlagGenerator(InputData, InputTemplate)

    def SingleRuleTest(self, InputData, InputRule):
        '单规则匹配函数，可根据需要在派生类里重写。本函数也是分析插件的入口位置'
        'Single rule test func, you may overwrite it in child class if necessary.'
        # 插件入口做在这里。如果规则包含一个有效的插件名，则执行插件分析逻辑，否则执行默认分析逻辑
        PluginObj = self._plugins.get(InputRule.get('PluginName', None), None)
        if PluginObj:
            return PluginObj.AnalyseSinlgeData(InputData, InputRule)
        else:
            return self._DefaultSingleRuleTest(InputData, InputRule)

    def PluginExec(self, PluginName, InputData, InputRule):
        '单独的插件执行函数，如果传入的插件名无效，返回(False, None)'
        # 该方法的应用场景是一个插件调用另一个插件的情况。
        # 如果用无效的插件名调用本函数，会抛出异常。
        # 因此需要由父级插件调用_plugins()属性检查调用的子插件是否存在或者捕获异常
        PluginObj = self._plugins.get(PluginName, None)
        if PluginObj:
            return PluginObj.AnalyseSinlgeData(InputData, InputRule)
        else:
            raise Exception("Plugin '%s' not found." % PluginName)

    def ClearCache(self):
        '清除缓存方法，重置缓存状态。可根据需要在派生类里重写'
        self._DefaultClearCache()

    def AnalyseMain(self, InputData, ActionFunc, InputRules):
        return self._DefaultAnalyseMain(InputData, ActionFunc, InputRules)

    def _DefaultAnalyseMain(self, InputData, ActionFunc, InputRules):
        '''默认的分析算法主函数。根据已经加载的规则和输入数据。
        基础分析算法判断是否匹配分为字段匹配和Flag匹配两部分，只有都匹配成功才算该条数据匹配成功。
        ActionFunc传入一个函数，该函数需要接收命中规则的数据inputData（dict）、对应命中的规则rule（dict）、命中的缓存对象hitItem(Obj)，生成的CurrentFlag（obj）作为参数,
        如果输入数据匹配成功，数据调用传入的ActionFunction()作为输出接口。每成功匹配一条规则，传入的ActionFunc()将被执行一次
        返回值是set()类型，包含了该条数据命中的所有CacheItem。如果没有命中返回长度为0的空集合（不是None）
        由于提供了单条规则匹配的方法，用户也可参考本函数自行实现分析函数

        Main function. Analyzing key-value based data (dict) with given rule set.
        Each time the input data hits a rule, ActionFunc() will be called once, use this as an output interface.
        Return a set() which includes all the CacheItem that input data hits, return an empty set() if input data hits nothing (not None).
        '''
        if InputRules == None:
            return None

        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, expecting dict()")

        rtn = set()  # 该条数据命中的缓存对象集合

        for rule in InputRules:  # 规则遍历主循环
            # 遍历检查单条规则
            # Tests every single rule on input data

            ruleCheckResult, hitItem = self.SingleRuleTest(InputData, rule)
            if ruleCheckResult:  # 字段匹配和前序Flag匹配均命中（包括前序Flag为空的情况），规则命中
                # 1、构造本级Flag；   Generate current flag;
                # 2、调用ActionFunc()获得用户数据，构造CacheItem对象；  Call ActionFunc() to get a user defined data
                # 3、以本级Flag作为Key，新的CacheItem作为Value，存入self._cache[]； Save cache item into self._cache[], with current flag as key
                currentFlag = self.FlagGenerator(InputData, rule["CurrentFlag"])
                newDataItem = ActionFunc(InputData, rule, hitItem, currentFlag)
                if currentFlag not in self._cache and currentFlag != None:
                    # 将命中规则的数据、规则本身、命中的缓存对象以及命中的Flag传给用户函数，获得用户函数返回值
                    # 如果是入口点规则，命中的缓存对象是None，用户函数可据此判断
                    # Passing the key data, hit rule itself, hit cache item (None if the data hits a init rule) and flag to ActionFunc()
                    if newDataItem != None:  # 用户层还可以再做一次判断，如果用户认为已经满足字段匹配和前序FLAG匹配的数据仍不符合分析条件，可返回None，缓存数据将不会被记录
                        newCacheItem = self.CacheItem(
                            currentFlag,
                            rule["FlagThrehold"],
                            rule["FlagLifetime"],
                            newDataItem)
                        # If the input data hits a certain rule and successfully generated a new CacheItem obj, the obj will be in the return.
                        self._cache[currentFlag] = newCacheItem
                        rtn.add(newCacheItem)
                        
                        Expire = rule.get('Expire', 0)
                        if type(Expire) in {int, float} and Expire > 0:
                        # 如果到期时间大于0，则为有效值，为FLAG设置有效期，并且即刻生效。
                            timer = threading.Timer(Expire, self.__RemoveFlag, {currentFlag})
                            self._timer[currentFlag] = timer
                            timer.start()
                            # 如果需要条件延迟启动定时器（比如threhold消耗完之后再启动），可设置两级串联规则。
                            # 第一级是延迟条件（比如设置threhold）；第二级规则无条件，带定时器。之间用flag关联
                else:
                    # Flag冲突时，检查FLAG是否对应一个定时器，命中规则是否带有超时规则。如果都具备，用当前规则的超时重置这个计数器
                    # if the new flag conflicts with a existed and timing flag, check and reset the flag's timer with the Expire given in the rule.
                    hitTimer = self._timer.get(currentFlag, None)
                    Expire = rule.get('Expire', 0)
                    if hitTimer != None and hitTimer.isAlive() and type(Expire) in {int, float} and Expire > 0:
                        hitTimer.cancel()
                        resetTimer = threading.Timer(Expire, self.__RemoveFlag, {currentFlag})
                        self._timer[currentFlag] = resetTimer
                        resetTimer.start()
                    pass
        return rtn