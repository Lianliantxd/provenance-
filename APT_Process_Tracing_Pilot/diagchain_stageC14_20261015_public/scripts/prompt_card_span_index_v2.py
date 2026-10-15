"""Exact card blocks and JSON lexical leaf spans in the frozen prompt string."""
from __future__ import annotations
import json
import re

MARKER="Retrieved evidence memory:\n"

def memory_segment(prompt: str) -> tuple[int,int,str]:
    if prompt.count(MARKER)!=1:return -1,-1,"BASELINE_SEGMENT_UNVERIFIED"
    start=prompt.index(MARKER)+len(MARKER)
    return start,len(prompt),"VERIFIED_TERMINAL_SEGMENT"

def card_blocks(prompt: str) -> dict[str, list[dict]]:
    start,end,status=memory_segment(prompt)
    if status!="VERIFIED_TERMINAL_SEGMENT":return {}
    segment=prompt[start:end];out={}
    full_marker="FULL_EVIDENCE_CARDS_NEWEST_WINDOW:"
    old_marker="SUMMARIZED_OLDER_EVIDENCE_CARDS:"
    if full_marker in segment:
        a=segment.index(full_marker)+len(full_marker)
        z=segment.index(old_marker,a) if old_marker in segment[a:] else len(segment)
        sub=segment[a:z];marks=list(re.finditer(r"(?m)^evidence_id: ([A-Za-z][A-Za-z0-9_-]*)\s*$",sub))
        for i,m in enumerate(marks):
            lo=start+a+m.start();hi=start+a+(marks[i+1].start() if i+1<len(marks) else len(sub))
            out.setdefault(m.group(1),[]).append({"start":lo,"end":hi,"form":"FULL_CARD","text":prompt[lo:hi]})
    if old_marker in segment:
        a=segment.index(old_marker)+len(old_marker)
        sub=segment[a:]
        for m in re.finditer(r"(?m)^([A-Za-z][A-Za-z0-9_-]*) \|[^\n]*",sub):
            lo=start+a+m.start();hi=start+a+m.end()
            out.setdefault(m.group(1),[]).append({"start":lo,"end":hi,"form":"SUMMARY_CARD","text":prompt[lo:hi]})
    return out

class LexicalJSON:
    def __init__(self,text: str,offset: int):
        self.s=text;self.i=0;self.base=offset;self.leaves=[]
    def ws(self):
        while self.i<len(self.s) and self.s[self.i].isspace():self.i+=1
    def string(self):
        start=self.i;value,end=json.JSONDecoder().raw_decode(self.s[self.i:])
        if not isinstance(value,str):raise ValueError("EXPECTED_STRING")
        self.i+=end;return value,start,self.i
    def value(self,path=""):
        self.ws();start=self.i
        if self.i>=len(self.s):raise ValueError("TRUNCATED_JSON")
        ch=self.s[self.i]
        if ch=="{":
            self.i+=1;self.ws()
            if self.i<len(self.s) and self.s[self.i]=="}":self.i+=1;return {}
            obj={}
            while True:
                self.ws();key,_,_=self.string();self.ws()
                if self.s[self.i]!=":":raise ValueError("NO_COLON")
                self.i+=1;child=f"{path}.{key}" if path else key
                obj[key]=self.value(child);self.ws()
                if self.s[self.i]=="}":self.i+=1;break
                if self.s[self.i]!=",":raise ValueError("NO_COMMA")
                self.i+=1
            return obj
        if ch=="[":
            self.i+=1;self.ws();arr=[]
            if self.i<len(self.s) and self.s[self.i]=="]":self.i+=1;return arr
            while True:
                arr.append(self.value(f"{path}[{len(arr)}]"));self.ws()
                if self.s[self.i]=="]":self.i+=1;break
                if self.s[self.i]!=",":raise ValueError("NO_COMMA")
                self.i+=1
            return arr
        value,end=json.JSONDecoder().raw_decode(self.s[self.i:])
        self.i+=end
        if isinstance(value,(dict,list)):raise ValueError("UNEXPECTED_CONTAINER")
        self.leaves.append({"field_path":path,"value":value,"start":self.base+start,"end":self.base+self.i})
        return value

def json_leaves(text: str,absolute_start: int) -> list[dict]:
    lex=LexicalJSON(text,absolute_start)
    try:
        lex.value();lex.ws()
        if lex.i!=len(text):return []
        return lex.leaves
    except (ValueError,IndexError,TypeError):return []
