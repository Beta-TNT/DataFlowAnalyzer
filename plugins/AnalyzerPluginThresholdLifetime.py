import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import AnalyseLib

class AnalysePlugin(AnalyseLib.AnalyseBase.PluginBase):
    '原基础算法中实现的Threshold和Lifetime功能，出于精简代码和数据结构考虑，单独拆分成插件'
    # 本插件只负责提供Flag是否有效，不提供Flag到应用层数据的映射关系
    # 通过规则的PrevFlag构造Flag-CacheItem映射
    # 以及规则的CurrentFlag去检查Flag-CacheItem映射是否满足条件
    # 如果不满足条件，返回False, None，否则返回True, hitItem

    class CacheItem(object):
        '实现Flag生命周期管理，业务层里作为Flag到用户数据对象之间的映射'
        # 注意，本插件生成的Threshold和Lifetime只有调用本插件的规则才有效，
        # 已经通过本插件生成的带有Threshold和Lifetime的Flag在原算法里仍然还是普通Flag，可以被直接操作或访问
        '''缓存对象CacheItem（命中后存储的Flag对应的数据）：
        Threshold    ： 门槛消耗剩余，来自触发这条规则的FlagThreshold字段。
                        Flag生成之后每次命中Threshold消耗1，直到Threshold变为0时这个Flag才能正式生效。
                        Flag判定时应判断Threshold是否为0，Threshold为0的Flag才是生效的Flag，否则将Flag的Threshold减1，并返回Flag未命中
        Lifetime    ：  生存期剩余，来自触发这条规则的FlagLifetime字段。
                        Flag生效之后（Threshold消耗完）每次命中Lifetime消耗1。
                        当最后一次命中之后Lifetime减0时这个Flag将被销毁。
                        Lifetime如果初始就是0，则为永久有效，跳过Lifetime判定和消耗流程。
        ExtraData   ：  附加数据，可存储业务需要的任何数据。
        FlagContent ：  对应Flag的内容'''
        _Threshold = 0  # 门槛剩余
        _LifeTime = 0  # 生存期剩余
        _FlagContent = ''  # Flag内容
        # _ExtraData = None  # 附加数据
        _Valid = True  # 指示当前Flag是否应还有效，当生存期消耗完毕或者超过有效时间时为False，其他情况包括门槛未消耗完毕时仍然为True。
        # 检查缓存对象是否可用应使用Check()函数，而不是直接使用_Valid属性

        # @property
        # def ExtraData(self):
        #     return self._ExtraData

        @property
        def ThresholdRemain(self):
            return self._Threshold

        @property
        def LifetimeRemain(self):
            return self._LifeTime

        @property
        def FlagContent(self):
            return self._FlagContent

        @property
        def Valid(self):
            return self._Valid

        def __init__(self, FlagContent, Threshold, LifeTime):
            self._Threshold = Threshold
            self._LifeTime = LifeTime
            self._FlagContent = FlagContent
            # self._ExtraData = ExtraData

        def _ConsumeThreshold(self):
            '消耗门槛操作，如果门槛已经消耗完毕，返回True。在门槛消耗完毕之前，Valid属性仍然是True'
            # 注意，如果设置了Threshold为N，Flag在第N+1次重复命中之后才会生效
            # 例：如果设置Threshold为1，则Flag在第二次重复命中的时候才会生效
            # 之所以这么设计，是考虑到当Threshold设置为0的时候，等价于即刻生效，下一次Flag命中即生效
            if self._Valid:
                if self._Threshold <= 0:
                    return True
                else:
                    self._Threshold -= 1
                    return False
            else:
                return False

        def _ConsumeLifetime(self):
            '消耗生存期操作。如果还在生存期内或者生存期无限（值为0）返回True，否则返回False并将Valid属性设为False'
            # Lifetime由1变成0的时候才会使得_Valid变为False，初始就是0时表示无限
            if self._Valid:
                if self._LifeTime > 0:
                    self._LifeTime -= 1
                    # 生存期失效之前最后一次调用，返回True并将_Valid设为False
                    self._Valid = not (self._LifeTime == 0)
                    # 特别注意，当规则设置Lifetime为1的时候，Flag仅在生效的那一个周期有效，过后即被销毁
                return True
            else:
                return False

        def Check(self):  # 检查是否有效
            if not self._Valid:
                return False
            else:
                if self._ConsumeThreshold():
                    return self._ConsumeLifetime()
                else:
                    return False

    _ExtraRuleFields = {
        "Threshold": (
            "Flag触发门槛，相同的Flag每次触发之后消耗1，消耗到0之后Flag才正式生效。默认值0即无门槛", 
            int
        ),
        "Lifetime": (
            "Flag生存期，Flag生效之后相同的Flag再命中多少次之后即失效。默认值0即生存期无限", 
            int
        )
    }

    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.basename(_PluginFilePath).split('.')[:-1][0]

    # 原分析算法基类中的Flag生命周期管理缓存对象，现拆分成单独的插件实现Threshold和Lifetime功能
    _cache = dict() # Flag-CacheItem映射
    
    def LoadSetting(self):
        'dummy loadsetting func.'
        pass

    def AnalyseSingleData(self, InputData, InputRule):
        return self._AnalyseSingleData(InputData, InputRule)

    def FlagPeek(self, InputFlag):
        '默认Flag偷窥函数，检查Flag是否有效，但并不会触发Threshold或Lifetime消耗，也不进行映射管理。对于Threshold不为0的Flag也返回缓存对象'
        if not InputFlag: #hitResult为True且前序Flag为空，为入口点规则
            return True, None
        else:
            rtn = False
            hitItem = self._cache.get(InputFlag)
            if hitItem:
                rtn = hitItem.Valid
            return rtn, hitItem

    def FlagCheck(self, InputFlag):
        '默认Flag检查函数，检查Flag是否有效，返回True/False。检查将完成Flag管理功能'
        rtn, hitItem = self.FlagPeek(InputFlag)
        if not rtn:
            if hitItem:
                self.RemoveFlag(InputFlag)
        else:
            if hitItem:
                rtn = hitItem.Check()
                if not hitItem.Valid:  
                    self.RemoveFlag(InputFlag)
            else: # hitResult为True且前序Flag为空，为入口点规则
                rtn = True
        return rtn

    def RemoveFlag(self, InputFlag):
        # 删除过期/无效的Flag，包括Flag-CacheItem映射和算法对象中的Flag
        self._cache.pop(InputFlag)
        self._AnalyseBase.RemoveFlag(InputFlag)

    def _AnalyseSingleData(self, InputData, InputRule):
        '插件数据分析方法用户函数，接收被分析的dict()类型数据和规则作为参考数据，由用户函数判定是否满足规则。返回值定义同_DefaultSingleRuleTest()函数'
        # 0、先调用默认的单规则匹配函数，获得当前规则/flag在基础算法中的匹配结果
        # 1、由于插件函数参数不包括PrevFlag，需要再构造一次PrevFlag，要求和主算法做匹配时构造的PrevFlag必须相同
        # 2、在插件内缓存中查找PrevFlag是否有效，完成Flag生存期管理
        # 3、如果有效，返回PrevFlag在插件内匹配结果以及原分析函数返回对象，否则返回False, None
        hitResult, hitItem = super()._DefaultAnalyseSingleData(InputData, InputRule)

        # 再次构造Flag。由于基础算法的FlagCheck在单规则匹配成功之后才进行
        # 因此可以在插件层对Flag进行“拦截”
        if hitResult and self.FlagCheck(self._AnalyseBase.FlagGenerator(InputData, InputRule.get('PrevFlag'))):
            # 在插件内构造Flag-CacheItem映射
            if InputRule.get("Threshold", 0) or InputRule.get("Lifetime", 0):
                # Threshold和Lifetime至少有一个不为0才进行Flag映射和管理
                currentFlag = self._AnalyseBase.FlagGenerator(InputData, InputRule.get('CurrentFlag'))
                newCacheItem = self.CacheItem(
                    currentFlag,
                    InputRule.get("Threshold", 0),
                    InputRule.get("Lifetime", 0),
                )
                self._cache[currentFlag] = newCacheItem
            return True, hitItem
        else:
            return False, None

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "Dummy plugin for test and sample."

    @property
    def ExtraRuleFields(self):
        '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
        return self._ExtraRuleFields