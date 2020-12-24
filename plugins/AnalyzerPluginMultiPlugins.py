import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from AnalyseLib import AnalyseBase

class AnalysePlugin(AnalyseBase.PluginBase):
    _SettingItems = {}
    _SettingItemProperties = {}
    _PluginFilePath = os.path.abspath(__file__)
    _CurrentPluginName = os.path.basename(_PluginFilePath).split('.')[:-1][0]

    _ExtraRuleFields = {
        "PluginNames": (
            '插件名称列表，分号分隔，当前规则需要包含所有插件所需的自定义字段，名字重复出现的插件将被执行多次，禁止套娃',
            str,
            lambda x: os.path.basename(os.path.abspath(__file__)).split('.')[:-1][0] not in x,
            '禁止套娃，多插件支持规则PluginNames中禁止出现多插件支持插件本身名称：%s'
        ),
        "MultiPluginMode": (
            '多插件运行模式。0=并行；1=串行。串行方式将按PluginNames列表顺序运行，下一个插件接收上一个插件对输入数据以及规则的修改；并行方式每个插件接受数据副本拷贝',
            int
        )
    }

    def LoadSetting(self):
        pass

    def AnalyseSingleData(self, InputData, InputRule):
        return self._AnalyseSingleData(InputData, InputRule)

    def _AnalyseSingleData(self, InputData, InputRule):
        '数据分析方法接口，接收被分析的dict()类型数据和规则作为参考数据'
        if InputRule.get('PluginNames'):
            pluginNameList = list(map(lambda str:str.strip(), InputRule['PluginNames'].split(';')))
            pluginResults = set()
            if InputRule['MultiPluginMode'] == 0: # 并行
                pluginResults = set(
                    map(
                        lambda x:self._AnalyseBase.PluginExec(x, InputData.copy(), InputRule.copy()),
                        pluginNameList
                    )
                )
            elif InputRule['MultiPluginMode'] == 1: # 串行
                i = 0
                while True:
                    if i>= len(pluginNameList):
                        break
                    pluginResults.add(self._AnalyseBase.PluginExec(pluginNameList[i], InputData, InputRule))
                    i += 1
            # 如果所有插件都返回了相同的返回值，即将该返回值作为最终的返回值，否则返回False, None
            rtn = (False, None) if len(pluginResults) != 1 else pluginResults.pop()
            return rtn
        else:
            return self._DefaultAnalyseSingleData(InputData, InputRule)

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "多插件支持插件，可以在一条规则使用多个插件"
