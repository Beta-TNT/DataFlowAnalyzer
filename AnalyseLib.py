'时序分析算法基础模块,实现最基础的业务无关的时序分析逻辑'

__author__ = 'Beta-TNT'

import re
from enum import IntEnum


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
    NotTextMatching = -2
    NotRegexMatching = -3
    LessThan = -4


class AnalyseBase(object):
    '时序分析算法核心类'

    '''规则字段结构（字典）：
    Operator    ：字段匹配运算，见OperatorCode
    PrevFlag    ：时序分析算法历史匹配Flag构造模板，为空则是入口点规则
    CurrentFlag ：时序分析算法本级规则命中后构造Flag的模板
    FlagThrehold：本级规则构造的Flag触发门槛。相同的Flag每次命中消耗1，消耗到0才能真正触发；默认0则不存在门槛，直接触发
    FlagLifetime：本级规则构造的Flag生存期。Flag被真正触发之后，相同的Flag再次触发会消耗1，消耗到0后Flag删除
    FieldCheckList[]    ：字段匹配项列表

    字段匹配项结构（字典）：
    FieldName   ：要进行匹配的字段名
    MatchContent：匹配内容
    MatchCode   ：匹配方式代码

    缓存数据结构CacheItem（命中后存储的Flag对应的数据）：
    Threhold    ：  门槛消耗剩余，来自触发这条规则的FlagThrehold字段。
                    Flag生成之后每次命中Threhold消耗1，直到Threhold变为0时这个Flag才能正式生效。
                    Flag判定时应判断Threhold是否为0，Threhold为0的Flag才是生效的Flag，否则将Flag的Threhold减1，跳过Flag判定环节。
    Lifetime    ：  生存期剩余，来自触发这条规则的FlagLifetime字段。
                    Flag生效之后（Threhold消耗完）每次命中Lifetime消耗1。
                    当最后一次命中之后Lifetime减0时这个Flag将被销毁。
                    Lifetime如果初始就是0，则为永久有效，跳过Lifetime判定和消耗流程。
    ExtraData   ：  附加数据，和存储业务需要的任何数据。
    FlagContent ：  对应Flag的内容
    '''

    class CacheItem(object):
        _Threhold = 0  # 门槛剩余
        _LifeTime = 0  # 生存期剩余
        _FlagContent = ''  # Flag内容
        _ExtraData = None  # 附加数据
        _Valid = True  # 指示当前Flag是否应还有效，当生存期消耗完毕时_Valid = False

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

        def _ConsumeThrehold(self):  # 消耗门槛操作，如果门槛已经消耗完毕，返回True
            if self._Valid == False:
                return False

            if self._Threhold <= 0:
                return True
            else:
                self._Threhold -= 1
                return False

        # 消耗生存期操作。如果还在生存期内或者生存期无限（值为0）返回True，否则返回false并将_Valid设为False
        def _ConsumeLifetime(self):
            if self._Valid == False:
                return False

            if self._LifeTime == 0:
                return True
            else:
                self._LifeTime -= 1
                if self._LifeTime == 0:  # 生存期失效之前最后一次调用，返回True并将_Valid设为False
                    self._Valid = False
                return True

        def Check(self):
            return self._DefaultCheck()

        def _DefaultCheck(self):  # 检查是否有效
            if self._Valid == False:
                return False
            else:
                if self._ConsumeThrehold():
                    return self._ConsumeLifetime()
                else:
                    return False

    _rules = None  # 规则列表
    _cache = None  # 缓存

    def __init__(self, InputRules):
        if type(InputRules) != list:
            raise TypeError('Invalid InputRules type, excepting list')
        self._rules = InputRules    # 规则列表
        self._cache = dict()        # 缓存

    def _DefaultFlagGenerator(self, InputData, InputTemplate):
        '默认的Flag生成函数，根据输入的数据和模板构造Flag。将模板里用大括号包起来的字段名替换为InputData对应字段的内容'
        if type(InputTemplate) != str:
            raise TypeError("Invalid Template type, excepting str")
        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, excepting dict")

        rtn = InputTemplate
        for inputDataKey in InputData:
            replacePattern = "{%s}" % inputDataKey
            replacement = ""
            if type(InputData[inputDataKey]) == bytes:
                replacement = InputData[inputDataKey].decode("utf-16")
            else:
                replacement = str(InputData[inputDataKey])
            rtn = rtn.replace(replacePattern, replacement)

        return rtn

    def FlagGenerator(self, InputData, InputTemplate):
        'Flag生成函数，可根据需要在派生类里重写'
        return self._DefaultFlagGenerator(InputData, InputTemplate)
    

    def SingleRuleTest(self, InputData, InputRule):
        '用数据匹配单条规则，如果数据匹配当前则，返回(True, 命中的缓存对象)，否则返回(False, None)'
        if type(InputData) != dict or type(InputRule) != dict:
            raise TypeError("Invalid InputData or InputRule type, expecting dict")

        fieldCheckResult = False
        if InputRule["FieldCheckList"]:
            for fieldChecker in InputRule["FieldCheckList"]:  # 字段检查遍历循环，用字段检查规则轮数据
                if fieldChecker["FieldName"] in InputData:
                    targetData = InputData.get(fieldChecker["FieldName"])
                    fieldCheckResult = self.FieldCheck(targetData, fieldChecker)

                if InputRule["Operator"] in {OperatorCode.OpOr, OperatorCode.OpNotOr} and fieldCheckResult or \
                    InputRule["Operator"] in {OperatorCode.OpAnd, OperatorCode.OpNotAnd} and not fieldCheckResult:
                    # Or/NotOr，  第一个True结果即可结束字段判断
                    # And/NotAnd，第一个False结果即可结束字段判断
                    # Field value tests would be ended at first true result on Or/NotOr, or first false result on And/NotAnd,
                    # the rest tests would be abanboned.
                    break

            if InputRule["Operator"] in {OperatorCode.OpNotAnd, OperatorCode.OpNotOr}:
                fieldCheckResult = not fieldCheckResult
        else:
            fieldCheckResult = True  # 字段匹配列表为空，直接判定字段匹配通过
        
        if not fieldCheckResult:
            return (False, None)

        if bool(InputRule["PrevFlag"]):  # 判断前序flag是否为空
            # 检查Flag缓存，如果成功，返回一个包含两个元素的Tuple，分别是命中结果（True/False）和命中的CacheItem对象
            return self.FlagCheck(self.FlagGenerator(InputData, InputRule["PrevFlag"]))
        else:  
            # 前序flag为空，入口点规则，Flag匹配过程直接命中，命中的CacheItem对象为None
            return (True, None)
        

    def AnalyseMain(self, InputData, ActionFunc):
        '''分析算法主函数。根据已经加载的规则和输入数据。
        基础分析算法判断是否匹配分为字段匹配和Flag匹配两部分，只有都匹配成功才算该条数据匹配成功。
        ActionFunc传入一个函数，该函数需要接收命中规则的数据inputData（dict）、对应命中的规则rule（dict）、命中的缓存对象hitItem(Obj)，生成的CurrentFlag（obj）作为参数,
        在匹配成功后运行，返回值将作为CacheItem的ExtraData存储进缓存。
        分析算法函数无返回值，通过匹配成功的数据调用传入的ActionFunction()作为输出接口。每成功匹配一条规则，传入的ActionFunc()将被执行一次
        由于提供了单条规则匹配的方法，用户也可参考本函数自行实现分析函数

        Main function. Analyze key-value based data (dict) with given rule set. This function has no return value,
        each time the input data hits a rule, ActionFunc() will be called once, use this as an output interface.
        '''

        if type(InputData) != dict:
            raise TypeError("Invalid InputData type, expecting dict")
        for rule in self._rules:  # 规则遍历主循环
            # 遍历检查单条规则
            ruleCheckResult, hitItem = self.SingleRuleTest(InputData, rule)

            if ruleCheckResult:  # 字段匹配和前序Flag匹配均命中（包括前序Flag为空的情况），规则命中
                # 1、构造本级Flag；   Generate current flag;
                # 2、调用ActionFunc()获得用户数据，构造CacheItem对象；  Call ActionFunc() to get a user defined data
                # 3、以本级Flag作为Key，新的CacheItem作为Value，存入self._cache[]； Save cache item into self._cache[], with current flag as key
                currentFlag = self.FlagGenerator(InputData, rule["CurrentFlag"])
                if currentFlag not in self._cache:
                    # 将命中规则的数据、规则本身、命中的缓存对象以及命中的Flag传给用户函数，获得用户函数返回值
                    # 如果是入口点规则，命中的缓存对象是None，用户函数可据此判断
                    newDataItem = ActionFunc(InputData, rule, hitItem, currentFlag)
                    if newDataItem != None: # 用户层还可以再做一次判断，如果数据不符合条件，返回None，数据将不会被记录
                        newCacheItem = self.CacheItem(currentFlag, rule["FlagThrehold"], rule["FlagLifetime"], newDataItem)
                        self._cache[currentFlag] = newCacheItem
                else:  # Flag冲突时，数据将被忽略
                    pass 
                    # self._cache[currentFlag] = newCacheItem

    def _DefaultFlagCheck(self, InputFlag):
        '默认Flag检查函数，检查Flag是否有效。返回一个Tuple，包括该Flag是否有效(Bool)，以及该Flag命中的缓存对象。如无命中返回(False, None)。检查将完成Flag管理功能'
        rtn = False
        hitItem = None
        if InputFlag in self._cache:  # Flag存在
            hitItem = self._cache[InputFlag]
            rtn = hitItem.Check()  # 检查Flag，命中返回True
            if hitItem.Valid == False:  # 删除过期Flag
                self._cache.pop(InputFlag)
            if not rtn:
                hitItem = None
        return rtn, hitItem

    def FlagCheck(self, InputFlag):
        'Flag检查函数，可根据需要在派生类里重写'
        return self._DefaultFlagCheck(InputFlag)

    def _DefaultFieldCheck(self, TargetData, InputFieldCheckRule):
        '默认的字段检查函数，输入字段的内容以及单条字段检查规则，返回True/False'
        if type(InputFieldCheckRule) != dict:
            raise TypeError("Invalid InputFieldCheckRule type, expecting dict")
        
        fieldCheckResult = False
        MatchContent = InputFieldCheckRule["MatchContent"]
        # 相等匹配 equal test
        if InputFieldCheckRule["MatchCode"] in {MatchMode.Equal, MatchMode.NotEqual}:
            if type(MatchContent) == type(TargetData):  # 同数据类型，直接判断
                fieldCheckResult = (MatchContent == TargetData)
            else:  # 不同数据类型，都转换成字符串判断
                fieldCheckResult = (str(MatchContent) == str(TargetData))

        # 文本匹配（字符串） text matching (ignore case)
        elif InputFieldCheckRule["MatchCode"] in {MatchMode.TextMatching, MatchMode.NotTextMatching}:
            if type(MatchContent) != str:
                MatchContent = str(MatchContent)
            if type(TargetData) != str:
                TargetData = str(TargetData)
            fieldCheckResult = (
                MatchContent.lower().find(TargetData.lower) != -1)

        # 正则匹配（字符串） regex match
        elif InputFieldCheckRule["MatchCode"] in {MatchMode.RegexMatching, MatchMode.NotRegexMatching}:
            if type(MatchContent) != str:
                MatchContent = str(MatchContent)
            if type(TargetData) != str:
                TargetData = str(TargetData)
            fieldCheckResult = (
                re.match(MatchContent, TargetData) != None)

        # 大小比较（数字，字符串尝试转换成数字，转换不成功略过该字段匹配）
        elif InputFieldCheckRule["MatchCode"] in {MatchMode.GreaterThan, MatchMode.LessThan}:
            if type(MatchContent) in {int, float} and type(TargetData) in {int, float}:
                fieldCheckResult = (MatchContent > TargetData)
            else:
                try:
                    fieldCheckResult = (int(MatchContent) > int(TargetData))
                except Exception as e:
                    pass

        if InputFieldCheckRule["MatchCode"] < 0:  # 负数代码，结果取反
            fieldCheckResult = not fieldCheckResult

        return fieldCheckResult

    def FieldCheck(self, TargetData, InputFieldCheckRule):
        '字段检查函数，可根据需要在派生类里重写'
        return self._DefaultFieldCheck(TargetData, InputFieldCheckRule)
