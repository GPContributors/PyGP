TAG_TYPE_PRIMITIVE = 0x0
TAG_TYPE_CONSTRUCTED = 0x1

TAG_SIZE_BIG_1 = 0x81
TAG_SIZE_BIG_2 = 0x82




class TLV:
    def __init__(self, data=None,  content=True):
        self.childs = [] 
        self.root = False
        self.tag = None
        self.type = None
        self.extended = None
        self.length = None
        self.total_size = None
        self.value = None
        self.parse(data, content)

    def parse(self, data,  content):
        if data == None:
            return
        
        size = len(data)
        
        i = 0
        if data[i]&0b00011111 == 0b00011111:
            self.extended = True
        else:
            self.extended = False

        self.type = (data[i]&0b00100000)>>5

        if self.extended:
            self.tag = 256 * data[i] + data[i+1]
            i += 2
        else:
            self.tag = data[i]    
            i += 1

        # Recursive extended size
        if data[i] == TAG_SIZE_BIG_1:
            self.length = data[i+1]
            i += 2
        elif data[i] == TAG_SIZE_BIG_2:
            self.length = 256 * data[i+1] + data[i+2]
            i += 3
        else:
            self.length = data[i]
            i += 1
    
        if content == True:
            self.value = data[i:i+self.length]
            i += self.length

            if self.type == TAG_TYPE_CONSTRUCTED and self.length == len(self.value):
                j = 0
                while j < self.length:
                    tlv = TLV(self.value[j:])
                    self.childs.append(tlv)
                    j += tlv.total_size

        self.total_size = i
    
    def getTAG(self):
        return "%.2X" % self.tag
    
    def getValue(self):
        value = ""
        for i in self.value:
            value = value +  ('%.2X' % (i))
        return value

    def list_childs_tlv(self, code=None):
        if code == None:
            return self.childs
        ret = []
        for c in self.childs:
            if c.code == code:
                ret.append(c)
        return ret
    
    def toString(self, deep):
        obj_rep = ""
        deep_str = deep*'    '
        
        obj_rep = obj_rep +  ('%s%.2X [%.2x] ' % (deep_str, self.tag, self.length))
        if self.type == TAG_TYPE_PRIMITIVE and self.value != None:
            #obj_rep = obj_rep +  ('%s' % (deep_str))
            for i in self.value:
                obj_rep = obj_rep +  ('%.2X' % (i))
            
                
        deep += 1
        
        for tlv in self.childs:
            obj_rep = obj_rep +  '\n' +  tlv.toString(deep)
        
        return obj_rep.upper()
                
    def __str__(self):
        return self.toString(0)

class TLVs(TLV):
    def parse(self, data, content=True):
        size = len(data)
        self.root = True
        self.type = TAG_TYPE_CONSTRUCTED
        i = 0
        while i < size:
            tag = TLV(data[i:], content)
            self.childs.append(tag)
            i += tag.total_size