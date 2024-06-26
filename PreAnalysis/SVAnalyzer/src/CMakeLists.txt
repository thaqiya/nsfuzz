set (SVAsource
  StaticMain.cpp
  Annotation.h
  Annotation.cpp
  Common.h
  Common.cpp
  Global.h
  StructAnalyzer.cpp
  StructAnalyzer.h
  CallGraph.h
  CallGraph.cpp
  DepAnalysis.cpp
  DepAnalysis.h
)

# target_link_libraries(SVAnalyzer
#   LLVMPasses)

  # Build libraries.
add_library (SVAObj OBJECT ${SVAsource})
# add_library (SVAShared SHARED $<TARGET_OBJECTS:SVAObj>)
add_library (SVAStatic STATIC $<TARGET_OBJECTS:SVAObj>)

# Build executable, SVAMain.
set (EXECUTABLE_OUTPUT_PATH ${SVA_BINARY_DIR})
# link_directories (${SVA_BINARY_DIR})
add_executable(SVAnalyzer ${SVAsource})
target_link_libraries(SVAnalyzer 
  LLVMAsmParser
  LLVMSupport
  LLVMCore
  LLVMAnalysis
  LLVMIRReader
  SVAStatic
  )
#target_include_directories(
#  static
#  PRIVATE
#  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
