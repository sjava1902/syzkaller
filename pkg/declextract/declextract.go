// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

func Run(out *Output, syscallRename map[string][]string) ([]byte, []*Interface, error) {
	ctx := &context{
		Output:        out,
		syscallRename: syscallRename,
		structs:       make(map[string]*Struct),
	}
	ctx.processIncludes()
	ctx.processEnums()
	ctx.processStructs()
	ctx.processSyscalls()
	ctx.processIouring()

	ctx.serialize()
	ctx.finishInterfaces()
	return ctx.descriptions.Bytes(), ctx.interfaces, errors.Join(ctx.errs...)
}

type context struct {
	*Output
	syscallRename map[string][]string // syscall function -> syscall names
	structs       map[string]*Struct
	interfaces    []*Interface
	descriptions  *bytes.Buffer
	errs          []error
}

func (ctx *context) error(msg string, args ...any) {
	ctx.errs = append(ctx.errs, fmt.Errorf(msg, args...))
}

func (ctx *context) processIncludes() {
	// These additional includes must be at the top, because other kernel headers
	// are broken and won't compile without these additional ones included first.
	ctx.Includes = append([]string{
		"vdso/bits.h",
		"linux/types.h",
		"net/netlink.h",
	}, ctx.Includes...)
	replaces := map[string]string{
		// Arches may use some includes from asm-generic and some from arch/arm.
		// If the arch used for extract used asm-generic for a header,
		// other arches may need arch/asm version of the header. So switch to
		// a more generic file name that should resolve correctly for all arches.
		"include/uapi/asm-generic/ioctls.h":  "asm/ioctls.h",
		"include/uapi/asm-generic/sockios.h": "asm/sockios.h",
	}
	for i, inc := range ctx.Includes {
		if replace := replaces[inc]; replace != "" {
			ctx.Includes[i] = replace
		}
	}
}

func (ctx *context) processEnums() {
	for _, enum := range ctx.Enums {
		enum.Name += autoSuffix
	}
}

func (ctx *context) processSyscalls() {
	var syscalls []*Syscall
	for _, call := range ctx.Syscalls {
		ctx.processFields(call.Args, "", false)
		fn := strings.TrimPrefix(call.Func, "__do_sys_")
		for _, name := range ctx.syscallRename[fn] {
			ctx.noteInterface(&Interface{
				Type:             IfaceSyscall,
				Name:             name,
				IdentifyingConst: "__NR_" + name,
				Files:            []string{call.SourceFile},
				Func:             call.Func,
				AutoDescriptions: true,
			})
			newCall := *call
			newCall.Func = name + autoSuffix
			syscalls = append(syscalls, &newCall)
		}
	}
	ctx.Syscalls = sortAndDedupSlice(syscalls)
}

func (ctx *context) processIouring() {
	for _, op := range ctx.IouringOps {
		ctx.noteInterface(&Interface{
			Type:             IfaceIouring,
			Name:             op.Name,
			IdentifyingConst: op.Name,
			Files:            []string{op.SourceFile},
			Func:             op.Func,
			Access:           AccessUser,
		})
	}
}

func (ctx *context) processStructs() {
	for _, str := range ctx.Structs {
		str.Name += autoSuffix
		ctx.structs[str.Name] = str
	}
	ctx.Structs = slices.DeleteFunc(ctx.Structs, func(str *Struct) bool {
		return str.ByteSize == 0 // Empty structs are not supported.
	})
	for _, str := range ctx.Structs {
		ctx.processFields(str.Fields, str.Name, true)
	}
}

func (ctx *context) processFields(fields []*Field, parent string, needBase bool) {
	counts := make([]*Field, len(fields))
	for _, f := range fields {
		f.Name = fixIdentifier(f.Name)
		if f.CountedBy != -1 {
			counts[f.CountedBy] = f
		}
	}
	for i, f := range fields {
		f.syzType = ctx.fieldType(f, counts[i], parent, needBase)
	}
}

func (ctx *context) fieldType(f, counts *Field, parent string, needBase bool) string {
	if f.BitWidth != 0 && !needBase {
		ctx.error("syscall arg %v is a bitfield", f.Name)
	}
	if f.BitWidth != 0 && f.Type.Int == nil {
		ctx.error("non-int field %v is a bitfield", f.Name)
	}
	if counts != nil && f.Type.Int == nil && f.Type.Ptr == nil {
		ctx.error("non-int/ptr field %v counts field %v", f.Name, counts.Name)
	}
	f.Name = strings.ToLower(f.Name)
	switch {
	case f.Type.Int != nil:
		return ctx.fieldTypeInt(f, counts, needBase)
	case f.Type.Ptr != nil:
		return ctx.fieldTypePtr(f, counts, parent)
	case f.Type.Array != nil:
		return ctx.fieldTypeArray(f, parent)
	case f.Type.Buffer != nil:
		return ctx.fieldTypeBuffer(f)
	case f.Type.Struct != "":
		return ctx.fieldTypeStruct(f)
	}
	ctx.error("field %v does not have type", f.Name)
	return ""
}

func (ctx *context) fieldTypeInt(f, counts *Field, needBase bool) string {
	t := f.Type.Int
	switch t.ByteSize {
	case 1, 2, 4, 8:
	default:
		ctx.error("field %v has unsupported size %v", f.Name, t.ByteSize)
	}
	if t.Enum != "" && counts != nil {
		ctx.error("field %v is both enum %v and counts field %v", f.Name, t.Enum, counts.Name)
	}
	baseType := fmt.Sprintf("int%v", t.ByteSize*8)
	// Note: we make all 8-byte syscall arguments intptr b/c for 64-bit arches it does not matter,
	// but for 32-bit arches int64 as syscall argument won't work. IIUC the ABI is that these
	// are split into 2 32-bit arguments.
	intptr := t.ByteSize == 8 && (!needBase || strings.Contains(t.Base, "long") &&
		!strings.Contains(t.Base, "long long"))
	if intptr {
		baseType = "intptr"
	}
	if t.isBigEndian && t.ByteSize != 1 {
		baseType += "be"
	}
	if f.BitWidth == t.ByteSize*8 {
		f.BitWidth = 0
	}
	if f.BitWidth != 0 {
		baseType += fmt.Sprintf(":%v", f.BitWidth)
	}
	unusedType := fmt.Sprintf("const[0 %v]", maybeBaseType(baseType, needBase))
	if f.IsAnonymous {
		return unusedType
	}
	if t.Enum != "" {
		t.Enum += autoSuffix
		return fmt.Sprintf("flags[%v %v]", t.Enum, maybeBaseType(baseType, needBase))
	}
	if counts != nil {
		return fmt.Sprintf("len[%v %v]", counts.Name, maybeBaseType(baseType, needBase))
	}
	if t.Name == "TODO" {
		return todoType
	}
	special := ""
	switch t.ByteSize {
	case 2:
		special = ctx.specialInt2(f.Name, t.Name, needBase)
	case 4:
		special = ctx.specialInt4(f.Name, t.Name, needBase)
	case 8:
		if intptr {
			special = ctx.specialIntptr(f.Name, t.Name, needBase)
		}
	}
	if special != "" {
		if f.BitWidth != 0 {
			// We don't have syntax to express this.
			ctx.error("field %v is both special %v and a bitfield", f.Name, special)
		}
		return special
	}
	if strings.HasSuffix(f.Name, "enabled") || strings.HasSuffix(f.Name, "enable") {
		return "bool" + strings.TrimPrefix(baseType, "int")
	}
	if strings.Contains(f.Name, "pad") || strings.Contains(f.Name, "unused") ||
		strings.Contains(f.Name, "_reserved") {
		return unusedType
	}
	return baseType
}

func (ctx *context) specialInt2(field, typ string, needBase bool) string {
	switch {
	case strings.Contains(field, "port"):
		return "sock_port"
	}
	return ""
}

func (ctx *context) specialInt4(field, typ string, needBase bool) string {
	switch {
	case strings.Contains(field, "ipv4"):
		return "ipv4_addr"
	case strings.HasSuffix(field, "_pid") || strings.HasSuffix(field, "_tid") ||
		strings.HasSuffix(field, "_pgid") || strings.HasSuffix(field, "_tgid") ||
		field == "pid" || field == "tid" || field == "pgid" || field == "tgid":
		return "pid"
	case strings.HasSuffix(field, "dfd") && !strings.HasSuffix(field, "oldfd") && !strings.HasSuffix(field, "pidfd"):
		return "fd_dir"
	case strings.HasSuffix(field, "ns_fd"):
		return "fd_namespace"
	case strings.HasSuffix(field, "_uid") || field == "uid" || field == "user" ||
		field == "ruid" || field == "euid" || field == "suid":
		return "uid"
	case strings.HasSuffix(field, "_gid") || field == "gid" || field == "group" ||
		field == "rgid" || field == "egid" || field == "sgid":
		return "gid"
	case strings.HasSuffix(field, "fd") || strings.HasPrefix(field, "fd_") ||
		strings.Contains(field, "fildes") || field == "fdin" || field == "fdout":
		return "fd"
	case strings.Contains(field, "ifindex") || strings.Contains(field, "dev_index"):
		return "ifindex"
	}
	return ""
}

func (ctx *context) specialIntptr(field, typ string, needBase bool) string {
	switch {
	case field == "sigsetsize":
		return fmt.Sprintf("const[8 %v]", maybeBaseType("intptr", needBase))
	}
	return ""
}

func (ctx *context) fieldTypePtr(f, counts *Field, parent string) string {
	t := f.Type.Ptr
	dir := "inout"
	if t.IsConst {
		dir = "in"
	}
	opt := ""
	// Use an opt pointer if the direct parent is the same as this node, or if the field name is next.
	// Looking at the field name is a hack, but it's enough to avoid some recursion cases,
	// e.g. for struct adf_user_cfg_section.
	if f.Name == "next" || parent != "" && parent == t.Elem.Struct+autoSuffix {
		opt = ", opt"
	}
	elem := &Field{
		Name: f.Name,
		Type: t.Elem,
	}
	return fmt.Sprintf("ptr[%v, %v %v]", dir, ctx.fieldType(elem, counts, parent, true), opt)
}

func (ctx *context) fieldTypeArray(f *Field, parent string) string {
	t := f.Type.Array
	elem := &Field{
		Name: f.Name,
		Type: t.Elem,
	}
	elemType := ctx.fieldType(elem, nil, parent, true)
	if t.MinSize == 1 && t.MaxSize == 1 {
		return elemType
	}
	bounds := ctx.bounds(f.Name, t.MinSize, t.MaxSize)
	return fmt.Sprintf("array[%v%v]", elemType, bounds)
}

func (ctx *context) fieldTypeBuffer(f *Field) string {
	t := f.Type.Buffer
	bounds := ctx.bounds(f.Name, t.MinSize, t.MaxSize)
	baseType := "string"
	if t.IsNonTerminated {
		baseType = "stringnoz"
	}
	switch {
	case !t.IsString:
		return fmt.Sprintf("array[int8 %v]", bounds)
	case strings.Contains(f.Name, "ifname") || strings.HasSuffix(f.Name, "dev_name"):
		return "devname"
	case strings.Contains(f.Name, "filename") || strings.Contains(f.Name, "pathname") ||
		strings.Contains(f.Name, "dir_name") || f.Name == "oldname" ||
		f.Name == "newname" || f.Name == "path":
		if !t.IsNonTerminated && bounds == "" {
			return "filename" // alias that is easier to read
		}
		return fmt.Sprintf("%v[filename %v]", baseType, bounds)
	}
	return baseType
}

func (ctx *context) fieldTypeStruct(f *Field) string {
	f.Type.Struct += autoSuffix
	if ctx.structs[f.Type.Struct].ByteSize == 0 {
		return "void"
	}
	return f.Type.Struct
}

func (ctx *context) bounds(name string, min, max int) string {
	if min < 0 || min > max {
		ctx.error("field %v has bad bounds %v:%v", name, min, max)
	}
	if max > min {
		return fmt.Sprintf(", %v:%v", min, max)
	}
	if max != 0 {
		return fmt.Sprintf(", %v", max)
	}
	return ""
}

const (
	autoSuffix = "$auto"
	todoType   = "auto_todo"
)

func fixIdentifier(name string) string {
	switch name {
	case "resource", "include", "define", "incdir", "syscall", "parent":
		return "_" + name
	}
	return name
}

func stringIdentifier(name string) string {
	for _, bad := range []string{" ", ".", "-"} {
		name = strings.ReplaceAll(name, bad, "_")
	}
	return strings.ToLower(name)
}

func maybeBaseType(baseType string, needBase bool) string {
	if needBase {
		return ", " + baseType
	}
	return ""
}

func comma(i int) string {
	if i == 0 {
		return ""
	}
	return ", "
}
