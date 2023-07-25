import json
from target_base import *
		

class Target_PrintWin32u(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["win32u.dll"]
		
		# Regex library name match pattern to add hooks on
		#self.libraries_regex = re.compile("^((?!kernel|user|ntdll).)*$",re.IGNORECASE) # match nothing
		self.libraries_regex = re.compile("a^", re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = []
		#self.functions = ["NtUserRegisterClassExWOW","NtUserFindExistingCursorIcon","NtUserGetDoubleClickTime","NtGdiGetFontData","NtGdiFlush","NtUserDeferWindowPosAndBand","NtUserSystemParametersInfoForDpi","NtGdiCreateDIBSection","NtGdiAlphaBlend","NtGdiSelectFont","NtUserInvalidateRgn","NtUserQueryWindow","NtUserBeginDeferWindowPos","NtUserEndDeferWindowPosEx","NtUserGetMenuBarInfo","NtGdiCombineRgn","NtUserCreateMenu","NtGdiGetCharSet","NtUserGetKeyboardLayout","NtUserMoveWindow","NtUserGetThreadState","NtUserDestroyCursor","NtGdiCreateCompatibleBitmap","NtGdiGetTextExtentExW","NtUserGetClassName","NtGdiGetAppClipBox","NtUserSetTimer","NtGdiCreateRectRgn","NtUserSetWindowCompositionAttribute","NtUserIsWindowBroadcastingDpiToChildren","NtUserKillTimer","NtGdiGetCharABCWidthsW","NtUserSetWindowLong","NtUserGetWindowCompositionAttribute","NtUserQueryInputContext","NtUserChangeWindowMessageFilterEx","NtGdiExcludeClipRect","NtGdiSetBoundsRect","NtGdiGetOutlineTextMetricsInternalW","NtUserGetKeyState","NtUserGetDCEx","NtUserGetAncestor","NtUserGetImeInfoEx","NtUserFindWindowEx","NtUserGetTitleBarInfo","NtUserSetWinEventHook","NtGdiDdDDIOpenAdapterFromDeviceName","NtGdiDdDDICloseAdapter","NtGdiGetTextCharsetInfo","NtGdiCreateSolidBrush","NtGdiDoPalette","NtGdiQueryFontAssocInfo","NtUserCalcMenuBar","NtUserGetIMEShowStatus","NtUserChangeWindowMessageFilter","NtUserShowCaret","NtUserCreateAcceleratorTable","NtUserUpdateWindow","NtUserPaintMenuBar","NtGdiStretchDIBitsInternal","NtUserGetWindowDC","NtGdiGetGlyphIndicesW","NtUserGetGUIThreadInfo","NtUserCheckImeShowStatusInThread","NtUserHideCaret","NtUserGetProcessWindowStation","NtGdiCreatePatternBrushInternal","NtGdiGetBoundsRect","NtUserGetKeyboardLayoutList","NtUserGetClassInfoEx","NtGdiFontIsLinked","NtUserUpdateInputContext","NtUserSetImeOwnerWindow","NtUserNotifyIMEStatus","NtUserSetParent","NtUserWindowFromDC","NtGdiTransformPoints","NtUserBuildHwndList","NtUserRemoteConnectState","NtUserThunkedMenuInfo","NtGdiInit","NtUserValidateTimerCallback","NtGdiAnyLinkedFonts","NtUserSetFocus","NtUserSetWindowFNID","NtUserRegisterLPK","NtGdiGetWidthTable","NtUserDisableProcessWindowFiltering","NtUserGetDpiForCurrentProcess","NtUserGetIconSize","NtUserAssociateInputContext","NtGdiGetCharWidthInfo","NtUserGetAtomName","NtUserSetProcessDpiAwarenessContext"]
		#self.functions = [x.lower() for x in self.functions]
		
		# Regex function name match pattern to add hooks on
		#self.functions_regex = re.compile(".*(encrypt|rc4|decrypt|receive).*",re.IGNORECASE)
		self.functions_regex = re.compile("Nt.*",re.IGNORECASE)
		#self.functions_regex = re.compile("a^", re.IGNORECASE) # match nothing

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb

	

	def breakpoint_hit(self, event_name, address, context, th):
		print(event_name)
		
		parameters = [ {"name": "Arg1", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg2", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg3", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg4", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },

						{"name": "Arg5", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ},

						{"name": "Arg6", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ }
		]

		[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
		arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

		print(arguments.ToString())

		return [arguments.GetFuzzBlockDescriptions(), event_name]



class Target_AttackWin32u(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["win32u.dll"]
		
		# Regex library name match pattern to add hooks on
		#self.libraries_regex = re.compile("^((?!kernel|user|ntdll).)*$",re.IGNORECASE) # match nothing
		self.libraries_regex = re.compile("a^", re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["NtUserRegisterClassExWOW","NtUserFindExistingCursorIcon","NtUserGetDoubleClickTime","NtGdiGetFontData","NtGdiFlush","NtUserDeferWindowPosAndBand","NtUserSystemParametersInfoForDpi","NtGdiCreateDIBSection","NtGdiAlphaBlend","NtGdiSelectFont","NtUserInvalidateRgn","NtUserQueryWindow","NtUserBeginDeferWindowPos","NtUserEndDeferWindowPosEx","NtUserGetMenuBarInfo","NtGdiCombineRgn","NtUserCreateMenu","NtGdiGetCharSet","NtUserGetKeyboardLayout","NtUserMoveWindow","NtUserGetThreadState","NtUserDestroyCursor","NtGdiCreateCompatibleBitmap","NtGdiGetTextExtentExW","NtUserGetClassName","NtGdiGetAppClipBox","NtUserSetTimer","NtGdiCreateRectRgn","NtUserSetWindowCompositionAttribute","NtUserIsWindowBroadcastingDpiToChildren","NtUserKillTimer","NtGdiGetCharABCWidthsW","NtUserSetWindowLong","NtUserGetWindowCompositionAttribute","NtUserQueryInputContext","NtUserChangeWindowMessageFilterEx","NtGdiExcludeClipRect","NtGdiSetBoundsRect","NtGdiGetOutlineTextMetricsInternalW","NtUserGetKeyState","NtUserGetDCEx","NtUserGetAncestor","NtUserGetImeInfoEx","NtUserFindWindowEx","NtUserGetTitleBarInfo","NtUserSetWinEventHook","NtGdiDdDDIOpenAdapterFromDeviceName","NtGdiDdDDICloseAdapter","NtGdiGetTextCharsetInfo","NtGdiCreateSolidBrush","NtGdiDoPalette","NtGdiQueryFontAssocInfo","NtUserCalcMenuBar","NtUserGetIMEShowStatus","NtUserChangeWindowMessageFilter","NtUserShowCaret","NtUserCreateAcceleratorTable","NtUserUpdateWindow","NtUserPaintMenuBar","NtGdiStretchDIBitsInternal","NtUserGetWindowDC","NtGdiGetGlyphIndicesW","NtUserGetGUIThreadInfo","NtUserCheckImeShowStatusInThread","NtUserHideCaret","NtUserGetProcessWindowStation","NtGdiCreatePatternBrushInternal","NtGdiGetBoundsRect","NtUserGetKeyboardLayoutList","NtUserGetClassInfoEx","NtGdiFontIsLinked","NtUserUpdateInputContext","NtUserSetImeOwnerWindow","NtUserNotifyIMEStatus","NtUserSetParent","NtUserWindowFromDC","NtGdiTransformPoints","NtUserBuildHwndList","NtUserRemoteConnectState","NtUserThunkedMenuInfo","NtGdiInit","NtUserValidateTimerCallback","NtGdiAnyLinkedFonts","NtUserSetFocus","NtUserSetWindowFNID","NtUserRegisterLPK","NtGdiGetWidthTable","NtUserDisableProcessWindowFiltering","NtUserGetDpiForCurrentProcess","NtUserGetIconSize","NtUserAssociateInputContext","NtGdiGetCharWidthInfo","NtUserGetAtomName","NtUserSetProcessDpiAwarenessContext"]
		self.functions = [x.lower() for x in self.functions]
		
		# Regex function name match pattern to add hooks on
		#self.functions_regex = re.compile(".*(encrypt|rc4|decrypt|receive).*",re.IGNORECASE)
		#self.functions_regex = re.compile(".*",re.IGNORECASE)
		self.functions_regex = re.compile("a^", re.IGNORECASE) # match nothing

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb

	

	def breakpoint_hit(self, event_name, address, context, th):
		#print(event_name)
		
		parameters = [ {"name": "Arg1", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg2", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg3", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },
						
						{"name": "Arg4", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ },

						{"name": "Arg5", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ},

						{"name": "Arg6", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "type_args": 0x20, "fuzz": FUZZ }
		]

		[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
		arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

		#print(arguments.ToString())

		return [arguments.GetFuzzBlockDescriptions(), event_name]
