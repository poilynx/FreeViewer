/* From https://stackoverflow.com/questions/19808054/convert-c-function-pointer-to-c-function-pointer */
#ifndef _GETCB_H_
#define _GETCB_H_
#include <type_traits>
#include <functional>

template<typename T>
struct ActualType {
	typedef T type;
};
template<typename T>
struct ActualType<T*> {
	typedef typename ActualType<T>::type type;
};

template<typename T, unsigned int n,typename CallerType>
struct Callback;

template<typename Ret, typename ... Params, unsigned int n,typename CallerType>
struct Callback<Ret(Params...), n,CallerType> {
	typedef Ret (*ret_cb)(Params...);
	template<typename ... Args>
		static Ret callback(Args ... args) {
			func(args...);
		}

	static ret_cb getCallback(std::function<Ret(Params...)> fn) {
		func = fn;
		return static_cast<ret_cb>(Callback<Ret(Params...), n,CallerType>::callback);
	}

	static std::function<Ret(Params...)> func;

};

template<typename Ret, typename ... Params, unsigned int n,typename CallerType>
std::function<Ret(Params...)> Callback<Ret(Params...), n,CallerType>::func;

#define GETCB(ptrtype,callertype) Callback<ActualType<ptrtype>::type,__COUNTER__,callertype>::getCallback

#endif /* _GETCB_H_ */
