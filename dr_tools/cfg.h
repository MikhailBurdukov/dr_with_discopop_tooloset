
#ifndef _CFG_H_
#define _CFG_H_ 1

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include "analysis_tool.h"
#include "raw2trace.h"
#include "raw2trace_directory.h"

class cfg_t : public analysis_tool_t {
public:
    // The module_file_path is optional and unused for traces with
    // OFFLINE_FILE_TYPE_ENCODINGS.
    // XXX: Once we update our toolchains to guarantee C++17 support we could use
    // std::optional here.
    cfg_t(const std::string &module_file_path, uint64_t skip_refs, uint64_t sim_refs,
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
 
    uintptr_t timestamp_;
    int64_t timestamp_record_ord_ = -1;
    int64_t version_record_ord_ = -1;
    int64_t filetype_record_ord_ = -1;
    bool has_modules_;
    memtrace_stream_t *serial_stream_ = nullptr;
    
   
    struct basic_block_t
    {
        /// Virtual address of the first and the last instruction in the basic block. 
        app_pc head,tail; 
        /// Outcoming edges from this bb.
        std::unordered_set<app_pc> edges;
        /// Number of instructions in the basic block.
        size_t instruction_count = 0;
        /// How many times this bb was executed
        size_t execution_count = 0;
        basic_block_t(app_pc _h, app_pc _t) : 
            head(_h) , tail(_t) { }
        basic_block_t() : 
            head(nullptr) , tail(nullptr) { }
    };
    using controll_flow_graph = std::unordered_map<app_pc, basic_block_t>;
    controll_flow_graph global_bbs;
    std::mutex lock;
    bool process_new_bb(controll_flow_graph& bbs, app_pc trace_pc, app_pc head, app_pc tail);
    bool append_additional_info(instr_t * instr, basic_block_t& bb);
    
private:
    static constexpr int RECORD_COLUMN_WIDTH = 12;
    static constexpr int INSTR_COLUMN_WIDTH = 12;
    static constexpr int TID_COLUMN_WIDTH = 11;
    
    struct shard_data_t {
        controll_flow_graph local_bbs;
        std::unordered_map<app_pc, bool> instr_cache;
        bool is_new_bb;
        app_pc last_bb_head = nullptr;
        app_pc last_bb_tail = nullptr;
    };

};

#endif /* _CFG_H_ */
