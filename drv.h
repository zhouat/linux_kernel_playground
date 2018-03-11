struct drv_req {
	unsigned long offset;
	void (*fn)(void);
};
