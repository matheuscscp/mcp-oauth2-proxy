package store

type Store interface {
	StoreTransaction(tx *Transaction) (string, error)
	StoreSession(s *Session) (string, error)
	RetrieveTransaction(key string) (*Transaction, bool)
	RetrieveSession(key string) (*Session, bool)
}
