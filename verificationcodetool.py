import random


class VerificationCodeTool(object):

    def get_code(self):
        code = []
        #循环生成五个随机数
        for i in range(5):
            code.append(str(random.randint(0, 9)))
    
        # print(code)
        # #将列表转换成字符串
        # print(''.join(code))
        v_code = ''.join(code)
        return v_code