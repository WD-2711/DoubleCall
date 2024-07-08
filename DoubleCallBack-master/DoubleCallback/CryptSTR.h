#include <tuple>
#include <iostream>
#include <array>
#include <utility>

// 模板类，typename 代表任意一个合法的 C++ 类型
// 使用示例 xorstr<char, len> encrypted(text, 'K'); 
template <typename value_type, size_t length>
class xorstr
{
private:
#define CountOf(align, size) ((((size + align - 1) / align) * align) / align)
	// static 代表在所有对象实例中只有一个副本
	// constexpr 代表编译时是常量表达式，可以在编译时计算，而不是在运行时计算
	static constexpr auto count = CountOf(8, sizeof(value_type[length]));
	uint64_t data[count];

	// __forceinline 强制内联函数
	// const 表示返回值只读
	// 表示 xor 加密，加密密钥是随机生成的，每次加密 uint64 大小的值
	__forceinline constexpr const uint64_t crypt(bool gg, const value_type* c, size_t i)
	{
		// key 可变
		if (gg) {
			// volatile 表示不要优化对变量的访问，表示该变量可在程序的其他线程中被异步修改
			// volatile 每次访问该变量时，编译器都会从内存中重新读取它的值，而不是使用存储在寄存器中的值
			// __TIME__ 是一个预处理器宏，它在编译时被替换为当前的编译时间，格式为 HH:MM:SS
			constexpr volatile uint64_t key = (
				(uint64_t)((__TIME__[0] * __TIME__[6]) + __TIME__[1]) << 56 |
				(uint64_t)((__TIME__[1] * __TIME__[6]) + __TIME__[0]) << 48 |
				(uint64_t)((__TIME__[3] * __TIME__[6]) + __TIME__[4]) << 40 |
				(uint64_t)((__TIME__[4] * __TIME__[6]) + __TIME__[3]) << 32 |
				(uint64_t)((__TIME__[0] * __TIME__[7]) + __TIME__[1]) << 24 |
				(uint64_t)((__TIME__[1] * __TIME__[7]) + __TIME__[0]) << 16 |
				(uint64_t)((__TIME__[3] * __TIME__[7]) + __TIME__[4]) << 8 |
				(uint64_t)((__TIME__[4] * __TIME__[7]) + __TIME__[3]) << 0);

			auto ptr = (const uint8_t*)c + (i * 8);
			uint8_t ret[8] = {
				((i * 8) + 0) < size() ? ptr[0] : (uint8_t)0,
				((i * 8) + 1) < size() ? ptr[1] : (uint8_t)0,
				((i * 8) + 2) < size() ? ptr[2] : (uint8_t)0,
				((i * 8) + 3) < size() ? ptr[3] : (uint8_t)0,
				((i * 8) + 4) < size() ? ptr[4] : (uint8_t)0,
				((i * 8) + 5) < size() ? ptr[5] : (uint8_t)0,
				((i * 8) + 6) < size() ? ptr[6] : (uint8_t)0,
				((i * 8) + 7) < size() ? ptr[7] : (uint8_t)0
			}; 
			
			return *(uint64_t*)&ret ^ key;
		}

		// key 不可变
		else {
			constexpr uint64_t key = (
				(uint64_t)((__TIME__[0] * __TIME__[6]) + __TIME__[1]) << 56 |
				(uint64_t)((__TIME__[1] * __TIME__[6]) + __TIME__[0]) << 48 |
				(uint64_t)((__TIME__[3] * __TIME__[6]) + __TIME__[4]) << 40 |
				(uint64_t)((__TIME__[4] * __TIME__[6]) + __TIME__[3]) << 32 |
				(uint64_t)((__TIME__[0] * __TIME__[7]) + __TIME__[1]) << 24 |
				(uint64_t)((__TIME__[1] * __TIME__[7]) + __TIME__[0]) << 16 |
				(uint64_t)((__TIME__[3] * __TIME__[7]) + __TIME__[4]) << 8 |
				(uint64_t)((__TIME__[4] * __TIME__[7]) + __TIME__[3]) << 0);

			auto ptr = (const uint8_t*)c + (i * 8);
			uint8_t ret[8] = {
				((i * 8) + 0) < size() ? ptr[0] : (uint8_t)0,
				((i * 8) + 1) < size() ? ptr[1] : (uint8_t)0,
				((i * 8) + 2) < size() ? ptr[2] : (uint8_t)0,
				((i * 8) + 3) < size() ? ptr[3] : (uint8_t)0,
				((i * 8) + 4) < size() ? ptr[4] : (uint8_t)0,
				((i * 8) + 5) < size() ? ptr[5] : (uint8_t)0,
				((i * 8) + 6) < size() ? ptr[6] : (uint8_t)0,
				((i * 8) + 7) < size() ? ptr[7] : (uint8_t)0
			}; 
			
			return *(uint64_t*)&ret ^ key;
		}

	}

	// 初始化 data 数组，将输入的字符串加密并赋给 data 字段
	template <size_t... indices>
	__forceinline constexpr xorstr(bool gg, const value_type(&str)[length], std::index_sequence<indices...>) :
		data{ crypt(gg, str, indices)... } { }

public:
	__forceinline constexpr xorstr(const value_type(&str)[length], bool local = true)
		: xorstr(local, str, std::make_index_sequence<count>()) {}

	__forceinline constexpr size_t size() {
		return sizeof(value_type[length]);
	}

	// 获取加密后的数据
	__forceinline const auto get() {
		return (const value_type*)data;
	}

	// 获取未加密的数据
	__forceinline const auto crypt_get()
	{
		constexpr volatile uint64_t key = (
			(uint64_t)((__TIME__[0] * __TIME__[6]) + __TIME__[1]) << 56 |
			(uint64_t)((__TIME__[1] * __TIME__[6]) + __TIME__[0]) << 48 |
			(uint64_t)((__TIME__[3] * __TIME__[6]) + __TIME__[4]) << 40 |
			(uint64_t)((__TIME__[4] * __TIME__[6]) + __TIME__[3]) << 32 |
			(uint64_t)((__TIME__[0] * __TIME__[7]) + __TIME__[1]) << 24 |
			(uint64_t)((__TIME__[1] * __TIME__[7]) + __TIME__[0]) << 16 |
			(uint64_t)((__TIME__[3] * __TIME__[7]) + __TIME__[4]) << 8 |
			(uint64_t)((__TIME__[4] * __TIME__[7]) + __TIME__[3]) << 0);

		volatile const size_t cnt = &data[count] - &data[0];
		for (size_t i = 0; i < cnt; data[i] ^= key, i++);
		return (const value_type*)data;
	}
};

#define E(s) xorstr(s).crypt_get()