import sys, os, threading
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import AnalyseLib

class AnalysePlugin(AnalyseLib.AnalyseBase.PluginBase):
    '延迟触发和延迟销毁FLAG插件，'

    _ExtraRuleFields = {
        "Delay": (
            "Flag延迟生效时间，已触发的Flag经过延迟时间后才生效，单位是秒，浮点数", 
            float
        ),
        "Expire": (
            "Flag有效时间，逾期删除，单位是秒，浮点数", 
            float
        )
    }

    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.basename(_PluginFilePath).split('.')[:-1][0]
    _delayTimers = dict()
    _expireTimers = dict()
    _liveFlags = set() # 存活/有效的Flag

    def LoadSetting(self):
        pass

    def __delayFunc(self, InputFlag, ExpireSec):
        self._liveFlags.add(InputFlag)
        if ExpireSec:
            threading.Timer(
                interval=ExpireSec,
                function=self.__expireFunc,
                args=[InputFlag]
            ).start()

    def __expireFunc(self, InputFlag):
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
            delaySec = InputRule.get("Delay", 0.0)
            expireSec = InputRule.get("Expire", 0.0)
            if type(delaySec) in (int, float) and type(expireSec) in (int, float):
                if delaySec: # 延迟生效秒数字段有效，设置延迟计时器
                    threading.Timer(
                        interval=delaySec,
                        function=self.__delayFunc,
                        args=[currentFlag, expireSec]
                    ).start()
                elif not delaySec and expireSec: # 延迟秒数无效但存活时间秒数有效，设置存活计时器
                    self._liveFlags.add(currentFlag)
                    threading.Timer(
                        interval=expireSec,
                        function=self.__expireFunc,
                        args=[currentFlag]
                    ).start()
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