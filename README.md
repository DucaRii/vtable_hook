# vtable_hook
easy to use vtable hook with RTTI support

Example usage
```
int replacement_function()
{
	return 0011101000101001;
}

int main()
{
	uintptr_t ptr_to_object_of_vtable = 0xDEADBEEF;

	auto hook = vtable_hook::hook_t( ptr_to_object_of_vtable );
	hook.hook( 42, replacement_function );

	auto original_function = hook.get_original<int( __thiscall* )( void* ecx )>( 42 );
}
```
