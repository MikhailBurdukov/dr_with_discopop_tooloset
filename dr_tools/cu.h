
#ifndef _CU_H_
#define _CU_H_ 1

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include "analysis_tool.h"
#include "raw2trace.h"
#include "raw2trace_directory.h"

class cu_t : public analysis_tool_t {
public:
    // The module_file_path is optional and unused for traces with
    // OFFLINE_FILE_TYPE_ENCODINGS.
    // XXX: Once we update our toolchains to guarantee C++17 support we could use
    // std::optional here.
    cu_t(const std::string &module_file_path, uint64_t skip_refs, uint64_t sim_refs,
           const std::string &syntax, unsigned int verbose,
           const std::string &alt_module_dir = "");
    std::string
    initialize_stream(memtrace_stream_t *serial_stream) override;
    bool
    parallel_shard_supported() override;
    void *
    parallel_shard_init_stream(int shard_index, void *worker_data,
                               memtrace_stream_t *shard_stream) override;
    bool
    parallel_shard_exit(void *shard_data) override;
    bool
    parallel_shard_memref(void *shard_data, const memref_t &memref) override;
    std::string
    parallel_shard_error(void *shard_data) override;
    bool
    process_memref(const memref_t &memref) override;
    bool
    print_results() override;

    bool process_new_bb(app_pc trace_pc);

    static constexpr int
    tid_column_width()
    {
        return TID_COLUMN_WIDTH;
    }

protected:
    
    
    
    bool
    should_skip(memtrace_stream_t *memstream, const memref_t &memref);

    /* We make this the first field so that dr_standalone_exit() is called after
     * destroying the other fields which may use DR heap.
     */
    struct dcontext_cleanup_last_t {
    public:
        ~dcontext_cleanup_last_t()
        {
            if (dcontext != nullptr)
                dr_standalone_exit();
        }
        void *dcontext = nullptr;
    };

    dcontext_cleanup_last_t dcontext_;

    // These are all optional and unused for OFFLINE_FILE_TYPE_ENCODINGS.
    // XXX: Once we update our toolchains to guarantee C++17 support we could use
    // std::optional here.
    std::string module_file_path_;
    std::unique_ptr<module_mapper_t> module_mapper_;
    raw2trace_directory_t directory_;

    unsigned int knob_verbose_;
    int trace_version_;
    static const std::string TOOL_NAME;
    uint64_t knob_skip_refs_;
    uint64_t skip_refs_left_;
    uint64_t knob_sim_refs_;
    uint64_t sim_refs_left_;
    bool refs_limited_;
    std::string knob_syntax_;
    std::string knob_alt_module_dir_;
    uint64_t num_disasm_instrs_;
    std::unordered_map<app_pc, std::string> disasm_cache_;
    memref_tid_t prev_tid_;
    uint64_t prev_record_ = 0;
    intptr_t filetype_;
    std::unordered_set<memref_tid_t> printed_header_;
    std::unordered_map<memref_tid_t, uintptr_t> last_window_;
    uintptr_t timestamp_;
    int64_t timestamp_record_ord_ = -1;
    int64_t version_record_ord_ = -1;
    int64_t filetype_record_ord_ = -1;
    bool has_modules_;
    memtrace_stream_t *serial_stream_ = nullptr;
    
   
    struct mem_acc_t
    {
        app_pc addr;
        bool is_read;
    };

    struct computation_unit_t
    {
        size_t cu_id;
        /// instruction which inside this cu. 
        std::unordered_set<app_pc> instructions;
        /// successors cus.
        std::unordered_set<size_t> successors;
        size_t readDataSize;
        size_t writeDataSize;
        
        
        computation_unit_t(instr_t * instr)
        {
            add(instr);
        }
        computation_unit_t() = default;
        
        inline void add_edge(size_t cu){
            successors.insert(cu);
        }

        inline void add(instr_t * instr) {
            instructions.insert(instr_get_app_pc(instr));
        }
        
    };

    std::mutex lock;
    std::unordered_map<size_t, computation_unit_t> g_cus;
    
    struct shard_data_t {
        size_t cus_count;
        std::unordered_map<size_t, computation_unit_t> cus;
        std::vector<app_pc> mem_accs;
        std::unordered_map<reg_t, size_t> reg_history;
        std::unordered_map<app_pc, size_t> mem_history;
        std::unordered_map<app_pc, bool> last_is_write;
        std::unordered_map<app_pc, instr_t *> instr_cache;
        instr_t * current_instr;
        bool is_new_bb;
        app_pc last_bb_head = nullptr;
        app_pc last_bb_tail = nullptr;
        std::ostream read_write_access;
    };
private:
    static constexpr int RECORD_COLUMN_WIDTH = 12;
    static constexpr int INSTR_COLUMN_WIDTH = 12;
    static constexpr int TID_COLUMN_WIDTH = 11;
    bool
    update_touched_memory_and_regs(shard_data_t * shard, instr_t * instr, size_t cu);
    void print_write_accesses(std::ostream& ostr, instr_t * instr, bool read, bool write );
    bool process_old_reference(shard_data_t * shard, instr_t* instr);
    

};

#endif /* _CU_H_ */
