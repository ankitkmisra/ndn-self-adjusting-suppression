#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! https://waf.io/book/index.html#_obtaining_the_waf_file

import os
import re
from waflib import Task
from waflib.TaskGen import extension
from waflib.Tools import c_preproc
from waflib import Utils
@extension('.rc')
def rc_file(self,node):
	obj_ext='.rc.o'
	if self.env.WINRC_TGT_F=='/fo':
		obj_ext='.res'
	rctask=self.create_task('winrc',node,node.change_ext(obj_ext))
	try:
		self.compiled_tasks.append(rctask)
	except AttributeError:
		self.compiled_tasks=[rctask]
re_lines=re.compile(r'(?:^[ \t]*(#|%:)[ \t]*(ifdef|ifndef|if|else|elif|endif|include|import|define|undef|pragma)[ \t]*(.*?)\s*$)|'r'(?:^\w+[ \t]*(ICON|BITMAP|CURSOR|HTML|FONT|MESSAGETABLE|TYPELIB|REGISTRY|D3DFX)[ \t]*(.*?)\s*$)',re.IGNORECASE|re.MULTILINE)
class rc_parser(c_preproc.c_parser):
	def filter_comments(self,node):
		code=node.read()
		if c_preproc.use_trigraphs:
			for(a,b)in c_preproc.trig_def:
				code=code.split(a).join(b)
		code=c_preproc.re_nl.sub('',code)
		code=c_preproc.re_cpp.sub(c_preproc.repl,code)
		ret=[]
		for m in re.finditer(re_lines,code):
			if m.group(2):
				ret.append((m.group(2),m.group(3)))
			else:
				ret.append(('include',m.group(5)))
		return ret
class winrc(Task.Task):
	run_str='${WINRC} ${WINRCFLAGS} ${CPPPATH_ST:INCPATHS} ${DEFINES_ST:DEFINES} ${WINRC_TGT_F} ${TGT} ${WINRC_SRC_F} ${SRC}'
	color='BLUE'
	def scan(self):
		tmp=rc_parser(self.generator.includes_nodes)
		tmp.start(self.inputs[0],self.env)
		return(tmp.nodes,tmp.names)
	def exec_command(self,cmd,**kw):
		if self.env.WINRC_TGT_F=='/fo':
			replace_cmd=[]
			incpaths=[]
			while cmd:
				flag=cmd.pop(0)
				if flag.upper().startswith('/I'):
					if len(flag)==2:
						incpaths.append(cmd.pop(0))
					else:
						incpaths.append(flag[2:])
				else:
					replace_cmd.append(flag)
			cmd=replace_cmd
			if incpaths:
				env=kw['env']=dict(kw.get('env')or self.env.env or os.environ)
				pre_includes=env.get('INCLUDE','')
				env['INCLUDE']=pre_includes+os.pathsep+os.pathsep.join(incpaths)
		return super(winrc,self).exec_command(cmd,**kw)
	def quote_flag(self,flag):
		if self.env.WINRC_TGT_F=='/fo':
			return flag
		return super(winrc,self).quote_flag(flag)
def configure(conf):
	v=conf.env
	if not v.WINRC:
		if v.CC_NAME=='msvc':
			conf.find_program('RC',var='WINRC',path_list=v.PATH)
			v.WINRC_TGT_F='/fo'
			v.WINRC_SRC_F=''
		else:
			conf.find_program('windres',var='WINRC',path_list=v.PATH)
			v.WINRC_TGT_F='-o'
			v.WINRC_SRC_F='-i'
