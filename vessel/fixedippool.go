package vessel

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/projecteru2/barrel/store"
	"github.com/projecteru2/barrel/types"
	"github.com/projecteru2/barrel/utils"
	"github.com/projecteru2/barrel/vessel/codec"
)

// FixedIPAllocator .
type FixedIPAllocator interface {
	CalicoIPAllocator
	AllocFixedIP(context.Context, types.IP) error
	UnallocFixedIP(context.Context, types.IP) error
	UpdateFixedIPAttribute(context.Context, types.IP, types.IPAttribute) error
	// Only assign when fixed ip is allocated
	AssignFixedIP(context.Context, types.IP) error
	UnassignFixedIP(context.Context, types.IP) error
	AllocFixedIPFromPools(ctx context.Context, pools []types.Pool) (types.IPAddress, error)
}

// FixedIPAllocatorImpl .
type FixedIPAllocatorImpl struct {
	CalicoIPAllocator
	store store.Store
}

// NewFixedIPAllocator .
func NewFixedIPAllocator(allocator CalicoIPAllocator, stor store.Store) FixedIPAllocator {
	return FixedIPAllocatorImpl{
		CalicoIPAllocator: allocator,
		store:             stor,
	}
}

// AssignFixedIP .
func (impl FixedIPAllocatorImpl) AssignFixedIP(ctx context.Context, ip types.IP) error {
	logger := impl.logger("AssignFixedIP")

	// First check whether the ip is assigned as fixed ip
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
		ok          bool
		err         error
	)

	if ok, err = impl.store.Get(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Get IPInfo error, cause=%v", err)
		return err
	} else if !ok {
		logger.Warnf(`IP is not allocated, {"PoolID": "%s", "Address": "%s"}`, ip.PoolID, ip.Address)
		return types.ErrFixedIPNotAllocated
	}
	if ipInfo.Status.Match(types.IPStatusInUse) {
		logger.Debug("IPStatusInUse")
		return types.ErrIPInUse
	}

	ipInfo.Status.Mark(types.IPStatusInUse)
	if ok, err = impl.store.Update(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Update IPInfo error, cause=%v", err)
		return err
	} else if !ok {
		// update failed, the ip is modified by another container
		return types.ErrIPInUse
	}

	return nil
}

// UnassignFixedIP .
func (impl FixedIPAllocatorImpl) UnassignFixedIP(ctx context.Context, ip types.IP) error {
	logger := impl.logger("UnassignFixedIP")
	logger.Debug("Start")

	// First check whether the ip is assigned as fixed ip
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
		ok          bool
		err         error
	)

	if ok, err = impl.store.Get(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Get IPInfo error, cause=%v", err)
		return err
	} else if !ok {
		logger.Warnf(`IP is not allocated, {"PoolID": "%s", "Address": "%s"}`, ip.PoolID, ip.Address)
		return types.ErrFixedIPNotAllocated
	}

	if !ipInfo.Status.Match(types.IPStatusInUse) {
		logger.Warnf(`FixedIP is already unassigned, {"PoolID": "%s", "Address": "%s"}`, ip.PoolID, ip.Address)
		return nil
	}

	ipInfo.Status.Unmark(types.IPStatusInUse)
	if ok, err = impl.store.Update(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Update IPInfo error, cause=%v", err)
		return err
	} else if !ok {
		return types.ErrIPInUse
	}

	return nil
}

// AllocFixedIP .
func (impl FixedIPAllocatorImpl) AllocFixedIP(ctx context.Context, ip types.IP) error {
	logger := impl.logger("AllocFixedIP")

	// First check whether the ip is assigned as fixed ip
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
		ok          bool
		err         error
	)
	if ok, err = impl.store.Get(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Get IPInfo error, cause=%v", err)
		return err
	}
	if ok {
		if ipInfo.Status.Match(types.IPStatusInUse) {
			return types.ErrIPInUse
		}
		logger.WithField(
			"PoolID", ip.PoolID,
		).WithField(
			"Address", ip.Address,
		).Warn("FixedIP is already allocated")
		return nil
	}

	return impl.allocFixedIP(ctx, ip, ipInfoCodec, logger)
}

// UnallocFixedIP .
func (impl FixedIPAllocatorImpl) UnallocFixedIP(ctx context.Context, ip types.IP) error {
	logger := impl.logger("UnallocFixedIP")

	// First check whether the ip is assigned as fixed ip
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
		ok          bool
		err         error
	)
	if ok, err = impl.store.Get(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Get IPInfo error, cause=%v", err)
		return err
	}

	if !ok {
		// The fixed ip is not allocated, so give a warning here
		logger.Warnf(`IP is not allocated, {"PoolID": "%s", "Address": "%s"}`, ip.PoolID, ip.Address)
		return types.ErrFixedIPNotAllocated
	}

	if ipInfo.Status.Match(types.IPStatusInUse) {
		return types.ErrIPInUse
	}

	// Lock the ip first
	ipInfo.Status.Mark(types.IPStatusInUse, types.IPStatusRetired)
	if ok, err = impl.store.Update(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Lock IPInfo failed, cause=%v", err)
	} else if !ok {
		return types.ErrIPInUse
	}

	// Now we remove the ipInfo
	if _, err = impl.store.Delete(ctx, ipInfoCodec); err != nil {
		logger.Errorf("Delete IPInfo failed, cause=%v", err)
		// The
		return err
	}

	// Now we free the address
	if err = impl.UnallocIP(ctx, ip); err != nil {
		logger.Errorf("Unalloc IP failed, cause=%v", err)
		return err
	}

	return nil
}

// UpdateFixedIPAttribute .
func (impl FixedIPAllocatorImpl) UpdateFixedIPAttribute(ctx context.Context, ip types.IP, update func(*types.IPAttribute) *types.IPAttribute) error {
	ctx = impl.context(ctx, "UpdateFixedIPAttribute")
	var (
		codec *codec.IPInfoCodec
		err   error
	)
	if codec, err = impl.getFixedIP(ctx, ip, false); err != nil {
		return err
	}
	if codec == nil {
		return types.ErrFixedIPNotAllocated
	}
	prevAttrs := codec.IPInfo.Attrs
	codec.IPInfo.Attrs = update(prevAttrs)
	if prevAttrs == nil && codec.IPInfo.Attrs == nil {
		return nil
	}
	return impl.store.Update(ctx, codec)
}

// AllocFixedIPFromPools .
func (impl FixedIPAllocatorImpl) AllocFixedIPFromPools(ctx context.Context, pools []types.Pool) (types.IPAddress, error) {
	logger := impl.logger("AllocFixedIPFromPools")
	var (
		ip  types.IPAddress
		err error
	)
	if ip, err = impl.AllocIPFromPools(ctx, pools); err != nil {
		return ip, err
	}
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
	)
	if err = impl.store.Put(ctx, ipInfoCodec); err != nil {
		if err := impl.UnallocIP(ctx, ip.IP); err != nil {
			logger.Errorf("UnallocIP error, cause=%v", err)
		}
		return ip, err
	}
	return ip, nil
}

func (impl FixedIPAllocatorImpl) getFixedIP(ctx context.Context, ip types.IP, alloIfAbsent bool) (*codec.IPInfoCodec, error) {
	logger := utils.LogEntry(ctx)
	// First check whether the ip is assigned as fixed ip
	var (
		ipInfo      = types.IPInfo{Address: ip.Address, PoolID: ip.PoolID}
		ipInfoCodec = &codec.IPInfoCodec{IPInfo: &ipInfo}
		ok          bool
		err         error
	)
	if ok, err = impl.store.Get(ctx, ipInfoCodec); err != nil {
		logger.WithError(err).Error("Get fixed-ip info error")
		return nil, err
	}
	if !ok {
		if !alloIfAbsent {
			return nil, nil
		}
		if err = impl.allocFixedIP(ctx, ip, ipInfoCodec); err != nil {
			return nil, err
		}
	}
	return ipInfoCodec, nil
}

func (impl FixedIPAllocatorImpl) allocFixedIP(ctx context.Context, ip types.IP, codec *codec.IPInfoCodec) error {
	logger := utils.LogEntry(ctx)

	if err := impl.AllocIP(ctx, ip); err != nil {
		logger.WithError(err).Error("Alloc IP error")
		return err
	}
	if err := impl.store.Put(ctx, codec); err != nil {
		logger.WithError(err).Error("Create FixedIPInfo error")
		return err
	}
	return nil
}

func (impl FixedIPAllocatorImpl) logger(method string) *log.Entry {
	return log.WithField("Receiver", "FixedIPAllocatorImpl").WithField("Method", method)
}

func (impl FixedIPAllocatorImpl) context(ctx context.Context, method string) context.Context {
	return utils.WithEntry(ctx, impl.logger(method))
}
