									有机会创建两个PG_CONTEXT
									这里会切换栈，因为那个函数太大，要扩充内核栈再调用
									通过KeExpandKernelStackAndCallout，然后call PatchGuardInitThunk，继而call PatchGuardInit
											|
KeInitAmd64SpecificState/(other?)-> KiFilterFiberContext -> PatchGuardInit(内核拖入IDA中看到的最大的一个函数)
					 (在我的RS5上，他就这一条路)


查找PgInitThunk发现还有一个除了KiFilterFiberContext的引用，还有一个叫sub_FFFFF80271A9822A，也会初始化pg，但是这个例程没有符号，
也没有引用。



CmpAppendDllSection->FsRtlMdlReadCompleteDevEx
									

