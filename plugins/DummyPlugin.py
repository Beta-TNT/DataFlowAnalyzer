import sys, os
sys.path.append('..')
import AnalyseLib

class AnalysePlugin(AnalyseLib.AnalyseBase.PluginBase):
    '插件基类'

    _ExtraRuleFields = {}
    _AnalyseBase = None # 插件实例化时需要分析算法对象实例

    def AnalyseSinlgeData(self, InputData, InputRule):
        '插件数据分析方法用户函数，接收被分析的dict()类型数据和规则作为参考数据，由用户函数判定是否满足规则。返回值定义同_DefaultSingleRuleTest()函数'
        # add your own data preprocess code here
        rtn = super()._DefaultAnalyseSingleData(InputData, InputRule)
        # add your own postprocess/function extension code here

        # you can even call other plugin func here like this.

        # try:
        #     self._AnalyseBase.PluginExec('OtherPluginName', InputData, InputRule)
        # except Exception:
        #     pass # "Sorry, the plugin you've called does not exist."
        return rtn

    @property
    def PluginInstructions(self):
        '插件介绍文字'
        return "Dummy plugin for test and sample."

    @property
    def ExtraRuleFields(self):
        '插件独有的扩展规则字段，应返回一个dict()，其中key是字段名称，value是说明文字。无扩展字段可返回None'
        return self._ExtraRuleFields
