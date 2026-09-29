package cert

type Waiter interface {
	Wait() error
	Stop()
}

type Requestable interface {
	Request() error
}

type RequestableWaiter interface {
	Requestable
	Waiter
}

type Renewable interface {
	Requestable
	Renew() error
}

type RenewableWaiter interface {
	Requestable
	Renew() error
	Waiter
}
