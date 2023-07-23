module ProfileTools

using Profile
using CodeTracking
using StatsBase
using InteractiveUtils
#using REPL.TerminalMenus

export @perf

# struct ProfileMenuEntry
#     name::
# end

# struct ProfileMenu <: TerminalMenus._ConfiguredMenu{TerminalMenus.Config}
#     config::TerminalMenus.Config
#     pagesize::Int
#     pageoffset::Int
#     selected::Int

#     options::Vector{ProfileMenuEntry}
# end


macro perf(expr)
    quote
        len_start = Profile.len_data()
        Profile.@profile $(esc(expr))
        len_end = Profile.len_data()

        printperf(len_start+1, len_end)
    end
end

function printperf(len_start, len_end)
    ips = terminalIPs(len_start, len_end)

    io = IOBuffer()
    io_colored = IOContext(io, :color => true)

    doit(ips, io_colored)
    flush(io)
    seek(io, 0)
    
    run(pipeline(io, `less -R -P "Profile Data - (q) to quit"`))
    return
end

## foreach line... print line... foreach asm

function terminalIPs(len_start=1, len_end=nothing)
    data = Profile.fetch(include_meta=true)
    len_end = isnothing(len_end) ? length(data) : len_end
    data = @view data[len_start:len_end]
    data = Profile.strip_meta(data)

    ips = UInt64[]
    first = true
    for ip in data
        if first
            push!(ips, ip)
            first = false
        else
            (ip == 0) && (first = true)
        end
    end

    ips
end

function doit(ips=terminalIPs(), io=stdout)
    mimap = Dict{Core.MethodInstance, Vector{Int}}()
    stmap = Dict{UInt64, Vector{StackTraces.StackFrame}}()

    cmap = countmap(ips)

    ignore = 0
    fromc = 0
    for ip in ips
        if haskey(stmap, ip)
            st = stmap[ip]
        else
            st = (stmap[ip] = StackTraces.lookup(ip))
        end
        if !st[end].from_c
            mi = st[end].linfo
            if !isnothing(mi)
                !haskey(mimap, mi) && (mimap[mi] = [])
                push!(mimap[mi], st[end].line)
            else
                #println(st)
                #println(">>> $mi")
                ignore += 1
            end
        else
            fromc += 1
            println(">>>>>>>>")
            map(f -> println("$f // $(f.pointer) :: $ip"), st)
        end
    end

    println("ignored $ignore // from_c $fromc")

    mimap_sorted = sort(collect(mimap), by=kv->length(kv[2]), rev=true)
    for (mi, lines) in mimap_sorted
        freqs = countmap(lines)
        total = length(lines)

        println(mi)

        i_indices, i_lines = instructionmap(mi)

        lineinstrs = Dict() # Dict{Int, Vector{String}}()
        for (fptr, asmlines) in zip(i_indices, i_lines)
            if !haskey(stmap, fptr)
                stmap[fptr] = StackTraces.lookup(fptr)
            end
            
            res = stmap[fptr]
            if res[end].linfo == mi
                line = res[end].line
                if !haskey(lineinstrs, line)
                    lineinstrs[line] = [(asmlines, fptr)]
                else
                    push!(lineinstrs[line], (asmlines, fptr))
                end
            end
        end

        src, startline = CodeTracking.definition(String, mi.def)

        print_header(io, mi, total, length(ips) - ignore)

        for (i, linestr) in enumerate(split(src, "\n"))
            lineno = startline + i - 1

            if i == 1
                dashes = "─" ^ (6 + length(string(lineno)))
                print(io, "└$(dashes)┐ \n")
            end

            prefix = ""
            color = :normal
            if haskey(freqs, lineno)
                frac = freqs[lineno]/total
                prefix = "$(round(frac*100, digits=1))%"
                color = frac >= 0.05 ? (:red) : (:green)
            end
            
            prefix = lpad(prefix, 6)

            printstyled(io, "$prefix ", color=:yellow, bold=true)
            print(io, "$(lineno)│ ")
            print(io, "$linestr\n")

            stripped = lstrip(linestr)

            if haskey(freqs, lineno) && haskey(lineinstrs, lineno)
                iter = lineinstrs[lineno]
                for (asmlines, fptr) in iter
                    for (i, asmline) in enumerate(asmlines)
                        if length(asmline) == 0 || asmline[1] != ';'
                            asmline = (" " ^ (stripped.offset - linestr.offset)) * lstrip(asmline)
                            
                            if haskey(cmap, fptr)
                                #print(io, cmap[fptr])
                                frac = cmap[fptr] / total
                                color = frac >= 0.05 ? (:red) : (:green)
                                prefix = "$(round(frac*100, digits=1))%"
                                prefix = lpad(prefix, 6)
                                if i == 1
                                    printstyled(io, prefix, color=color)
                                elseif i == length(asmline)
                                    printstyled(io, "    │ ", color=color)
                                else
                                    printstyled(io, "    └─", color=color)
                                end
                            else
                                print(io, "      ")
                            end

                            print(io, " " ^ (1 + ndigits(lineno)))
                            print(io, "│ ")
                            printstyled(io, asmline, color=:light_blue)
                            println(io)
                        end
                    end
                end
            end
        end

        println(io)
    end
end

function print_header(io, mi::Core.MethodInstance, nsamples, ntotal)
    fname, line = functionloc(mi)

    path = length(relpath(fname)) < length(fname) ? relpath(fname) : fname
    dirname, file = splitdir(path)

    print(io, "┌╴ ")
    Base.with_output_color(
        (_io) -> Base.show_tuple_as_call(_io, mi.def.name, mi.specTypes; qualified=true),
        :light_cyan, io,
        bold=true
    )
    println(io)

    print(io, "├╴ ")
    printstyled(io, dirname * Base.Filesystem.pathsep(), color=:light_black)
    printstyled(io, file, bold=true)
    printstyled(io, ":$(line)\n", color=:light_black)

    print(io, "├╴ ")
    samplepct = round(100 * nsamples / ntotal, digits=1)
    printstyled(io, "$nsamples samples ($(samplepct)%)\n", color=:light_black)
end

abstract type CodeLocation end

struct PointerCodeLocation <: CodeLocation
    ip::UInt64
end

struct LineCodeLocation <: CodeLocation
    line::Int
end

struct CodeTable{T <: PointerCodeLocation}
    locations::Vector{T}
    code::Vector{Vector{SubString}}
end

function instructionmap(linfo)
    world = Base.get_world_counter()
    str = InteractiveUtils._dump_function_linfo_native(linfo, world, false, :att, :default, true)

    ptr::UInt64 = 0
    indices, lines = UInt64[], Vector{SubString}[]
    for line in split(str, "\n")
        code_origin_match = match(r"^; code origin: ([0-9a-fA-F]+)", line)
        if !isnothing(code_origin_match)
            ptr = parse(UInt64, code_origin_match[1], base=16)
            indices, lines = [ptr], [[line]]
            continue
        end

        instr_addr_match = match(r"^; ([0-9a-fA-F]+): ([0-9a-fA-F]+)", line)
        if !isnothing(instr_addr_match)
            addr = parse(UInt64, instr_addr_match[1], base=16)
            mask = UInt64(0xFFFF)
            ptr = (ptr & ~mask) | (addr & mask)
            if indices[end] != ptr
                push!(indices, ptr)
                push!(lines, [])
            end
        elseif length(line) > 0 && line[1] != ';'
            (ptr != 0) && push!(lines[end], line)
        end

    end

    return indices, lines
end

end # module ProfileTools
