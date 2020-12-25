import sys, os, threading
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import AnalyseLib

class AnalysePlugin(AnalyseLib.AnalyseBase.PluginBase):
    '延迟生效和过期销毁FLAG插件，'

    _ExtraRuleFields = {
        "Delay": (
            "Flag延迟生效时间，当前规则生效之后生成的CurrentFlag经过延迟时间后才生效，单位是秒，浮点数", 
            float
        ),
        "Expire": (
            "Flag有效时间，过期删除，单位是秒，浮点数", 
            float
        )
    }

    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.splitext(os.path.basename(_PluginFilePath))[0]
    _delayTimers = dict()
    _expireTimers = dict()
    _liveFlags = set() # 存活/有效的Flag

    def LoadSetting(self):
        pass

    def __delayFunc(self, InputFlag, ExpireSec):
        # 延迟生效计时器函数，将Flag设置为生效并启动过期计时器
        self._liveFlags.add(InputFlag)
        if ExpireSec:
            threading.Timer(
                interval=ExpireSec,
                function=self.__expireFunc,
                args=[InputFlag]
            ).start()

    def __expireFunc(self, InputFlag):
        # 过期计时器函数，将Flag从插件缓存以及分析器对象缓存中删除
        if InputFlag in self._liveFlags:
            self._liveFlags.remove(InputFlag)
        self._AnalyseBase.RemoveFlag(InputFlag)
        pass
    
    def AnalyseSingleData(self, InputData, InputRule):
        return self._AnalyseSingleData(InputData, InputRule)

    def _AnalyseSingleData(self, InputData, InputRule):
        '插件数据分析方法用户函数，接收被分析的dict()类型数据和规则作为参考数据，由用户函数判定是否满足规则。返回值定义同_DefaultSingleRuleTest()函数'
        hitResult, hitItem = super()._DefaultAnalyseSingleData(InputData, InputRule)
        # flag check
        prevFlag = self._AnalyseBase.FlagGenerator(InputData, InputRule.get('PrevFlag'))
        if hitResult and (prevFlag in self._liveFlags or not prevFlag):
            # 生成本级规则Flag
            currentFlag = self._AnalyseBase.FlagGenerator(InputData, InputRule.get('CurrentFlag'))
            delaySec = InputRule.get("Delay", 0)
            expireSec = InputRule.get("Expire", 0)
            if {type(delaySec),type(expireSec)}.issubset({int, float}) and currentFlag not in self._liveFlags:
                #字段类型判断，以及忽略已存在的Flag防止重复
                if delaySec: # 延迟生效秒数字段有效，设置延迟计时器
                    threading.Timer(
                        interval=delaySec,
                        function=self.__delayFunc,
                        args=[currentFlag, expireSec]
                    ).start()
                elif not delaySec and expireSec: # 延迟秒数无效但过期时间秒数有效，设置过期计时器
                    self.__delayFunc(currentFlag, expireSec)
                else: # 两者都无效，功能同普通规则，插件内不做记录
                    pass
            return True, hitItem
        else:
            return False, None

        return hitResult

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "Dummy plugin for test and sample."

    @property
    def ExtraRuleFields(self):
        '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
        return self._ExtraRuleFields