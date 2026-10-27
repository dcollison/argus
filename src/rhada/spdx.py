"""SPDX licence normalisation, compound expression analysis, risk classification, and copyright extraction."""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from license_expression import (
    AND,
    OR,
    ExpressionError,
    LicenseSymbol,
    LicenseWithExceptionSymbol,
    get_spdx_licensing,
)

from rhada.models import LicenseInfo, LicenseRiskCategory

_SPDX_LICENSING = get_spdx_licensing()

# Mapping of common raw licence names and Trove classifiers to canonical SPDX identifiers
RAW_TO_SPDX: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "the mit license (mit)": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "apache": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "asl 2": "Apache-2.0",
    "apache-1.1": "Apache-1.1",
    "apache 1.1": "Apache-1.1",
    "apache license 1.1": "Apache-1.1",
    "apache software license 1.1": "Apache-1.1",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "modified bsd license": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "2-clause bsd license": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd license": "BSD-2-Clause",
    "0bsd": "0BSD",
    "zero-clause bsd": "0BSD",
    "isc": "ISC",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "python software foundation": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "zlib": "Zlib",
    "zlib/libpng license": "Zlib",
    "mpl-2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "eclipse public license": "EPL-2.0",
    "cddl-1.0": "CDDL-1.0",
    "lgpl": "LGPL-2.1-or-later",
    "lgplv2": "LGPL-2.0-or-later",
    "lgplv2+": "LGPL-2.0-or-later",
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.0-only": "LGPL-2.0-only",
    "lgpl-2.0-or-later": "LGPL-2.0-or-later",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1-only": "LGPL-2.1-only",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1-or-later",
    "gnu lesser general public license v2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "lgpl-3.0-or-later": "LGPL-3.0-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gpl": "GPL-3.0-or-later",
    "gplv2": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "agpl": "AGPL-3.0-or-later",
    "agplv3": "AGPL-3.0-only",
    "agplv3+": "AGPL-3.0-or-later",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "agpl-3.0-or-later": "AGPL-3.0-or-later",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "gpl-3.0-with-gcc-exception": "GPL-3.0-with-GCC-exception",
    "sspl-1.0": "SSPL-1.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "public domain": "Public-Domain",
    "public-domain": "Public-Domain",
    "blessing": "blessing",
    "hpnd": "HPND",
    "historical permission notice and disclaimer (hpnd)": "HPND",
    "artistic-2.0": "Artistic-2.0",
    "bsl-1.0": "BSL-1.0",
    "boost": "BSL-1.0",
    "boost software license": "BSL-1.0",
    "boost software license 1.0": "BSL-1.0",
    "boost software license - version 1.0": "BSL-1.0",
    "mit-0": "MIT-0",
    "python-2.0": "Python-2.0",
    "python 2.0": "Python-2.0",
    "proprietary": "LicenseRef-Proprietary",
    "commercial": "LicenseRef-Proprietary",
    "other/proprietary license": "LicenseRef-Proprietary",
    "intel-simplified-software-license": "LicenseRef-Intel-Simplified-Software-License",
    "intel simplified software license": "LicenseRef-Intel-Simplified-Software-License",
    "issl": "LicenseRef-Intel-Simplified-Software-License",
    "intel-smpl": "LicenseRef-Intel-Simplified-Software-License",
    "intel-smpl-2018": "LicenseRef-Intel-Simplified-Software-License",
    "licenseref-intel-simplified-software-license": "LicenseRef-Intel-Simplified-Software-License",
}

TROVE_CLASSIFIER_MAP: dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU General Public License (GPL)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "License :: Public Domain": "Public-Domain",
    "License :: OSI Approved :: Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: Other/Proprietary License": "LicenseRef-Proprietary",
}

PERMISSIVE_SPDX = {
    "MIT",
    "Apache-2.0",
    "Apache-1.1",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "ISC",
    "PSF-2.0",
    "BSL-1.0",
    "MIT-0",
    "Python-2.0",
    "Zlib",
    "HPND",
    "Artistic-2.0",
    "GPL-3.0-with-GCC-exception",
    "OpenSSL",
    "Unicode-DFS-2016",
    "Unicode-3.0",
    "bzip2-1.0.6",
    "libpng-2.0",
    "IJG",
    "libtiff",
}

PUBLIC_DOMAIN_SPDX = {
    "Unlicense",
    "CC0-1.0",
    "Public-Domain",
    "blessing",
}

WEAK_COPYLEFT_SPDX = {
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
}

STRONG_COPYLEFT_SPDX = {
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "SSPL-1.0",
    "Sleepycat",
}

RISK_SEVERITY_ORDER: dict[LicenseRiskCategory, int] = {
    LicenseRiskCategory.PUBLIC_DOMAIN: 0,
    LicenseRiskCategory.PERMISSIVE: 1,
    LicenseRiskCategory.WEAK_COPYLEFT: 2,
    LicenseRiskCategory.UNKNOWN: 3,
    LicenseRiskCategory.PROPRIETARY: 4,
    LicenseRiskCategory.STRONG_COPYLEFT: 5,
}


class NativeLibraryProfile(NamedTuple):
    """Canonical profile for well-known native shared libraries."""

    canonical_name: str
    spdx_id: str
    homepage: str
    copyright_notice: str
    license_text: str
    source_url: str = ""


KNOWN_NATIVE_LIBRARIES: dict[str, NativeLibraryProfile] = {
    "libscipy_openblas": NativeLibraryProfile(
        canonical_name="openblas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.openblas.net/",
        copyright_notice="Copyright (c) 2011-2024, The OpenBLAS Project. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "scipy_openblas": NativeLibraryProfile(
        canonical_name="openblas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.openblas.net/",
        copyright_notice="Copyright (c) 2011-2024, The OpenBLAS Project. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libopenblas": NativeLibraryProfile(
        canonical_name="openblas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.openblas.net/",
        copyright_notice="Copyright (c) 2011-2024, The OpenBLAS Project. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "openblas": NativeLibraryProfile(
        canonical_name="openblas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.openblas.net/",
        copyright_notice="Copyright (c) 2011-2024, The OpenBLAS Project. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "liblapack": NativeLibraryProfile(
        canonical_name="lapack",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/lapack/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee and The University of Tennessee Research Foundation. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "lapack": NativeLibraryProfile(
        canonical_name="lapack",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/lapack/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee and The University of Tennessee Research Foundation. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libmkl": NativeLibraryProfile(
        canonical_name="mkl",
        spdx_id="LicenseRef-Intel-Simplified-Software-License",
        homepage="https://www.intel.com/content/www/us/en/developer/tools/oneapi/onemkl.html",
        copyright_notice="Copyright (C) 1999-2024 Intel Corporation. All rights reserved.",
        license_text="Intel Simplified Software License: Use and redistribution are permitted subject to Intel's license terms.",
    ),
    "mkl": NativeLibraryProfile(
        canonical_name="mkl",
        spdx_id="LicenseRef-Intel-Simplified-Software-License",
        homepage="https://www.intel.com/content/www/us/en/developer/tools/oneapi/onemkl.html",
        copyright_notice="Copyright (C) 1999-2024 Intel Corporation. All rights reserved.",
        license_text="Intel Simplified Software License: Use and redistribution are permitted subject to Intel's license terms.",
    ),
    "libf77blas": NativeLibraryProfile(
        canonical_name="blas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/blas/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libcblas": NativeLibraryProfile(
        canonical_name="blas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/blas/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libblas": NativeLibraryProfile(
        canonical_name="blas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/blas/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "blas": NativeLibraryProfile(
        canonical_name="blas",
        spdx_id="BSD-3-Clause",
        homepage="https://www.netlib.org/blas/",
        copyright_notice="Copyright (c) 1992-2024 The University of Tennessee. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libgfortran": NativeLibraryProfile(
        canonical_name="libgfortran",
        spdx_id="GPL-3.0-with-GCC-exception",
        homepage="https://gcc.gnu.org/fortran/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="GCC Runtime Library Exception v3.1: You have permission to propagate a work of Target Code formed by combining the Runtime Library with Independent Modules.",
    ),
    "libquadmath": NativeLibraryProfile(
        canonical_name="libquadmath",
        spdx_id="LGPL-2.1-or-later",
        homepage="https://gcc.gnu.org/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="The GNU Quad-Precision Math Library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any later version.",
        source_url="https://github.com/gcc-mirror/gcc/tree/master/libquadmath",
    ),
    "libgomp": NativeLibraryProfile(
        canonical_name="libgomp",
        spdx_id="GPL-3.0-with-GCC-exception",
        homepage="https://gcc.gnu.org/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="GCC Runtime Library Exception v3.1: You have permission to propagate a work of Target Code formed by combining the Runtime Library with Independent Modules.",
    ),
    "libiomp5": NativeLibraryProfile(
        canonical_name="openmp",
        spdx_id="Apache-2.0 WITH LLVM-exception",
        homepage="https://openmp.llvm.org/",
        copyright_notice="Copyright (c) LLVM Project and OpenMP Contributors. All rights reserved.",
        license_text="Licensed under the Apache License v2.0 with LLVM Exceptions.",
    ),
    "libomp": NativeLibraryProfile(
        canonical_name="openmp",
        spdx_id="Apache-2.0 WITH LLVM-exception",
        homepage="https://openmp.llvm.org/",
        copyright_notice="Copyright (c) LLVM Project and OpenMP Contributors. All rights reserved.",
        license_text="Licensed under the Apache License v2.0 with LLVM Exceptions.",
    ),
    "libatomic": NativeLibraryProfile(
        canonical_name="libatomic",
        spdx_id="GPL-3.0-with-GCC-exception",
        homepage="https://gcc.gnu.org/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="GCC Runtime Library Exception v3.1: You have permission to propagate a work of Target Code formed by combining the Runtime Library with Independent Modules.",
    ),
    "libwinpthread": NativeLibraryProfile(
        canonical_name="winpthreads",
        spdx_id="MIT",
        homepage="https://www.mingw-w64.org/",
        copyright_notice="Copyright (c) 2011-2024 mingw-w64 project. Permission is hereby granted, free of charge, to deal in the Software without restriction.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction.",
    ),
    "libfftw3": NativeLibraryProfile(
        canonical_name="fftw",
        spdx_id="GPL-2.0-or-later",
        homepage="https://www.fftw.org/",
        copyright_notice="Copyright (c) 2003, 2007-14 Matteo Frigo; Copyright (c) 2003, 2007-14 Massachusetts Institute of Technology.",
        license_text="FFTW is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.",
    ),
    "libqhull": NativeLibraryProfile(
        canonical_name="qhull",
        spdx_id="BSD-3-Clause",
        homepage="http://www.qhull.org/",
        copyright_notice="Copyright (c) 1993-2020 C.B. Barber, Arlington, MA and The Geometry Center, University of Minnesota.",
        license_text="Qhull is free software; redistribution and use in source and binary forms are permitted provided that the Qhull copyright notice and disclaimer are retained.",
    ),
    "libsuperlu": NativeLibraryProfile(
        canonical_name="superlu",
        spdx_id="BSD-3-Clause",
        homepage="https://portal.nersc.gov/project/sparse/superlu/",
        copyright_notice="Copyright (c) 2003, The Regents of the University of California, through Lawrence Berkeley National Laboratory.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libarpack": NativeLibraryProfile(
        canonical_name="arpack-ng",
        spdx_id="BSD-3-Clause",
        homepage="https://github.com/opencollab/arpack-ng",
        copyright_notice="Copyright (c) 1996-2008 Rice University. Developed by D.C. Sorensen, R.B. Lehoucq, C. Yang, and K. Maschhoff.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libhighs": NativeLibraryProfile(
        canonical_name="highs",
        spdx_id="MIT",
        homepage="https://highs.dev/",
        copyright_notice="Copyright (c) 2018-2024 HiGHS Developers.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction.",
    ),
    "libumfpack": NativeLibraryProfile(
        canonical_name="suitesparse-umfpack",
        spdx_id="GPL-2.0-or-later",
        homepage="https://people.engr.tamu.edu/davis/suitesparse.html",
        copyright_notice="Copyright (c) 1995-2024, Timothy A. Davis. All Rights Reserved.",
        license_text="UMFPACK is licensed under the GNU General Public License v2 or later.",
    ),
    "libcholmod": NativeLibraryProfile(
        canonical_name="suitesparse-cholmod",
        spdx_id="LGPL-2.1-or-later",
        homepage="https://people.engr.tamu.edu/davis/suitesparse.html",
        copyright_notice="Copyright (c) 2005-2024, University of Florida, Timothy A. Davis, and William W. Hager.",
        license_text="CHOLMOD is licensed under the GNU Lesser General Public License v2.1 or later.",
        source_url="https://github.com/DrTimothyAldenDavis/SuiteSparse/tree/master/CHOLMOD",
    ),
    "libsuitesparseconfig": NativeLibraryProfile(
        canonical_name="suitesparse",
        spdx_id="BSD-3-Clause",
        homepage="https://people.engr.tamu.edu/davis/suitesparse.html",
        copyright_notice="Copyright (c) 2012-2024, Timothy A. Davis.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libcolamd": NativeLibraryProfile(
        canonical_name="suitesparse",
        spdx_id="BSD-3-Clause",
        homepage="https://people.engr.tamu.edu/davis/suitesparse.html",
        copyright_notice="Copyright (c) 1998-2024, Timothy A. Davis and Stefan Larimore.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libamd": NativeLibraryProfile(
        canonical_name="suitesparse",
        spdx_id="BSD-3-Clause",
        homepage="https://people.engr.tamu.edu/davis/suitesparse.html",
        copyright_notice="Copyright (c) 1996-2024, Timothy A. Davis, Patrick R. Amestoy, and Iain S. Duff.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libssl": NativeLibraryProfile(
        canonical_name="openssl",
        spdx_id="Apache-2.0",
        homepage="https://www.openssl.org/",
        copyright_notice="Copyright (c) 1998-2024 The OpenSSL Project. All rights reserved.",
        license_text="Licensed under the Apache License 2.0 (the 'License'). You may not use this file except in compliance with the License.",
    ),
    "libcrypto": NativeLibraryProfile(
        canonical_name="openssl",
        spdx_id="Apache-2.0",
        homepage="https://www.openssl.org/",
        copyright_notice="Copyright (c) 1998-2024 The OpenSSL Project. All rights reserved.",
        license_text="Licensed under the Apache License 2.0 (the 'License'). You may not use this file except in compliance with the License.",
    ),
    "libzstd": NativeLibraryProfile(
        canonical_name="zstd",
        spdx_id="BSD-3-Clause",
        homepage="https://facebook.github.io/zstd/",
        copyright_notice="Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.",
        license_text="BSD License: Redistribution and use in source and binary forms, with or without modification, are permitted.",
    ),
    "libz": NativeLibraryProfile(
        canonical_name="zlib",
        spdx_id="Zlib",
        homepage="https://zlib.net/",
        copyright_notice="Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler",
        license_text="This software is provided 'as-is', without any express or implied warranty. Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the Zlib license restrictions.",
    ),
    "zlib": NativeLibraryProfile(
        canonical_name="zlib",
        spdx_id="Zlib",
        homepage="https://zlib.net/",
        copyright_notice="Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler",
        license_text="This software is provided 'as-is', without any express or implied warranty. Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the Zlib license restrictions.",
    ),
    "libffi": NativeLibraryProfile(
        canonical_name="libffi",
        spdx_id="MIT",
        homepage="https://sourceware.org/libffi/",
        copyright_notice="Copyright (c) 1996-2024 Anthony Green, Red Hat, Inc and others.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.",
    ),
    "libexpat": NativeLibraryProfile(
        canonical_name="expat",
        spdx_id="MIT",
        homepage="https://libexpat.github.io/",
        copyright_notice="Copyright (c) 1998-2000 Thai Open Source Software Center Ltd and Clark Cooper. Copyright (c) 2001-2024 Expat maintainers.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction.",
    ),
    "libsqlite3": NativeLibraryProfile(
        canonical_name="sqlite3",
        spdx_id="blessing",
        homepage="https://www.sqlite.org/",
        copyright_notice="Public Domain - D. Richard Hipp and SQLite contributors",
        license_text="The author disclaims copyright to this source code. In place of a legal notice, here is a blessing: May you do good and not evil.",
    ),
    "sqlite3": NativeLibraryProfile(
        canonical_name="sqlite3",
        spdx_id="blessing",
        homepage="https://www.sqlite.org/",
        copyright_notice="Public Domain - D. Richard Hipp and SQLite contributors",
        license_text="The author disclaims copyright to this source code. In place of a legal notice, here is a blessing: May you do good and not evil.",
    ),
    "liblzma": NativeLibraryProfile(
        canonical_name="xz",
        spdx_id="0BSD",
        homepage="https://tukaani.org/xz/",
        copyright_notice="Copyright (C) Lasse Collin and Jia Tan",
        license_text="Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.",
    ),
    "libbz2": NativeLibraryProfile(
        canonical_name="bzip2",
        spdx_id="BSD-3-Clause",
        homepage="https://sourceware.org/bzip2/",
        copyright_notice="Copyright (C) 1996-2019 Julian R Seward. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libgmp": NativeLibraryProfile(
        canonical_name="gmp",
        spdx_id="LGPL-3.0-or-later",
        homepage="https://gmplib.org/",
        copyright_notice="Copyright 1991-2023 Free Software Foundation, Inc.",
        license_text="The GNU Multiple Precision Arithmetic Library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.",
        source_url="https://gmplib.org/#DOWNLOAD",
    ),
    "libreadline": NativeLibraryProfile(
        canonical_name="readline",
        spdx_id="GPL-3.0-or-later",
        homepage="https://tiswww.case.edu/php/chet/readline/rltop.html",
        copyright_notice="Copyright (C) 1987-2023 Free Software Foundation, Inc.",
        license_text="GNU Readline is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3, or (at your option) any later version.",
    ),
    "libgcc_s": NativeLibraryProfile(
        canonical_name="libgcc",
        spdx_id="GPL-3.0-with-GCC-exception",
        homepage="https://gcc.gnu.org/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="GCC Runtime Library Exception v3.1: You have permission to propagate a work of Target Code formed by combining the Runtime Library with Independent Modules.",
    ),
    "libstdc++": NativeLibraryProfile(
        canonical_name="libstdc++",
        spdx_id="GPL-3.0-with-GCC-exception",
        homepage="https://gcc.gnu.org/",
        copyright_notice="Copyright (C) Free Software Foundation, Inc.",
        license_text="GCC Runtime Library Exception v3.1: You have permission to propagate a work of Target Code formed by combining the Runtime Library with Independent Modules.",
    ),
    "libpython": NativeLibraryProfile(
        canonical_name="python",
        spdx_id="PSF-2.0",
        homepage="https://www.python.org/",
        copyright_notice="Copyright (c) 2001-2026 Python Software Foundation. All Rights Reserved.",
        license_text="PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2",
    ),
    "libpng": NativeLibraryProfile(
        canonical_name="libpng",
        spdx_id="libpng-2.0",
        homepage="http://www.libpng.org/pub/png/libpng.html",
        copyright_notice="Copyright (c) 1995-2024 The PNG Reference Library Authors.",
        license_text="This code is released under the libpng license.",
    ),
    "png": NativeLibraryProfile(
        canonical_name="libpng",
        spdx_id="libpng-2.0",
        homepage="http://www.libpng.org/pub/png/libpng.html",
        copyright_notice="Copyright (c) 1995-2024 The PNG Reference Library Authors.",
        license_text="This code is released under the libpng license.",
    ),
    "libjpeg": NativeLibraryProfile(
        canonical_name="libjpeg",
        spdx_id="IJG",
        homepage="https://ijg.org/",
        copyright_notice="Copyright (C) 1991-2024, Thomas G. Lane, Guido Vollbeding.",
        license_text="This software is based in part on the work of the Independent JPEG Group.",
    ),
    "jpeg": NativeLibraryProfile(
        canonical_name="libjpeg",
        spdx_id="IJG",
        homepage="https://ijg.org/",
        copyright_notice="Copyright (C) 1991-2024, Thomas G. Lane, Guido Vollbeding.",
        license_text="This software is based in part on the work of the Independent JPEG Group.",
    ),
    "libtiff": NativeLibraryProfile(
        canonical_name="libtiff",
        spdx_id="libtiff",
        homepage="http://www.libtiff.org/",
        copyright_notice="Copyright (c) 1988-1997 Sam Leffler; Copyright (c) 1991-1997 Silicon Graphics, Inc.",
        license_text="Permission to use, copy, modify, distribute, and sell this software and its documentation for any purpose is hereby granted.",
    ),
    "tiff": NativeLibraryProfile(
        canonical_name="libtiff",
        spdx_id="libtiff",
        homepage="http://www.libtiff.org/",
        copyright_notice="Copyright (c) 1988-1997 Sam Leffler; Copyright (c) 1991-1997 Silicon Graphics, Inc.",
        license_text="Permission to use, copy, modify, distribute, and sell this software and its documentation for any purpose is hereby granted.",
    ),
    "libwebp": NativeLibraryProfile(
        canonical_name="libwebp",
        spdx_id="BSD-3-Clause",
        homepage="https://chromium.googlesource.com/webm/libwebp",
        copyright_notice="Copyright (c) 2010, Google Inc. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "webp": NativeLibraryProfile(
        canonical_name="libwebp",
        spdx_id="BSD-3-Clause",
        homepage="https://chromium.googlesource.com/webm/libwebp",
        copyright_notice="Copyright (c) 2010, Google Inc. All rights reserved.",
        license_text="Redistribution and use in source and binary forms, with or without modification, are permitted provided that the BSD 3-Clause conditions are met.",
    ),
    "libopencv": NativeLibraryProfile(
        canonical_name="opencv",
        spdx_id="Apache-2.0",
        homepage="https://opencv.org/",
        copyright_notice="Copyright (C) 2000-2024, Intel Corporation, OpenCV Foundation. All rights reserved.",
        license_text="Licensed under the Apache License, Version 2.0.",
    ),
    "opencv": NativeLibraryProfile(
        canonical_name="opencv",
        spdx_id="Apache-2.0",
        homepage="https://opencv.org/",
        copyright_notice="Copyright (C) 2000-2024, Intel Corporation, OpenCV Foundation. All rights reserved.",
        license_text="Licensed under the Apache License, Version 2.0.",
    ),
    "liblcms2": NativeLibraryProfile(
        canonical_name="lcms2",
        spdx_id="MIT",
        homepage="https://www.littlecms.com/",
        copyright_notice="Copyright (c) 1998-2024 Marti Maria Saguer. All rights reserved.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software.",
    ),
    "lcms2": NativeLibraryProfile(
        canonical_name="lcms2",
        spdx_id="MIT",
        homepage="https://www.littlecms.com/",
        copyright_notice="Copyright (c) 1998-2024 Marti Maria Saguer. All rights reserved.",
        license_text="Permission is hereby granted, free of charge, to any person obtaining a copy of this software.",
    ),
    "libtorch_cpu": NativeLibraryProfile(
        canonical_name="torch",
        spdx_id="BSD-3-Clause",
        homepage="https://pytorch.org/",
        copyright_notice="Copyright (c) 2016-present, Facebook Inc, PyTorch contributors.",
        license_text="PyTorch BSD 3-Clause License.",
    ),
    "torch_cpu": NativeLibraryProfile(
        canonical_name="torch",
        spdx_id="BSD-3-Clause",
        homepage="https://pytorch.org/",
        copyright_notice="Copyright (c) 2016-present, Facebook Inc, PyTorch contributors.",
        license_text="PyTorch BSD 3-Clause License.",
    ),
    "c10": NativeLibraryProfile(
        canonical_name="torch",
        spdx_id="BSD-3-Clause",
        homepage="https://pytorch.org/",
        copyright_notice="Copyright (c) 2016-present, Facebook Inc, PyTorch contributors.",
        license_text="PyTorch BSD 3-Clause License.",
    ),
    "libc10": NativeLibraryProfile(
        canonical_name="torch",
        spdx_id="BSD-3-Clause",
        homepage="https://pytorch.org/",
        copyright_notice="Copyright (c) 2016-present, Facebook Inc, PyTorch contributors.",
        license_text="PyTorch BSD 3-Clause License.",
    ),
    "arrow": NativeLibraryProfile(
        canonical_name="arrow",
        spdx_id="Apache-2.0",
        homepage="https://arrow.apache.org/",
        copyright_notice="Copyright 2016-2024 The Apache Software Foundation.",
        license_text="Licensed under the Apache License, Version 2.0.",
    ),
    "libarrow": NativeLibraryProfile(
        canonical_name="arrow",
        spdx_id="Apache-2.0",
        homepage="https://arrow.apache.org/",
        copyright_notice="Copyright 2016-2024 The Apache Software Foundation.",
        license_text="Licensed under the Apache License, Version 2.0.",
    ),
    "geos_c": NativeLibraryProfile(
        canonical_name="geos",
        spdx_id="LGPL-2.1-only",
        homepage="https://libgeos.org/",
        copyright_notice="Copyright (C) 2006 Refractions Research Inc.",
        license_text="GEOS is licensed under the GNU Lesser General Public License Version 2.1.",
        source_url="https://github.com/libgeos/geos",
    ),
    "libgeos_c": NativeLibraryProfile(
        canonical_name="geos",
        spdx_id="LGPL-2.1-only",
        homepage="https://libgeos.org/",
        copyright_notice="Copyright (C) 2006 Refractions Research Inc.",
        license_text="GEOS is licensed under the GNU Lesser General Public License Version 2.1.",
        source_url="https://github.com/libgeos/geos",
    ),
}

# Reverse mapping from directory / module names to canonical Python package names
MODULE_TO_KNOWN_PACKAGE: dict[str, str] = {
    "pil": "pillow",
    "cv2": "cv2",
    "opencv_python": "opencv-python",
    "opencv_python_headless": "opencv-python",
    "bs4": "beautifulsoup4",
    "crypto": "pycryptodome",
    "cryptodome": "pycryptodomex",
    "jwt": "pyjwt",
    "nacl": "pynacl",
    "openssl": "pyopenssl",
    "serial": "pyserial",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "usb": "pyusb",
    "yaml": "pyyaml",
    "_yaml": "pyyaml",
    "sklearn": "scikit-learn",
    "attr": "attrs",
}

# Canonical mapping from known native library names/stems to origin Python packages
KNOWN_LIBRARY_TO_PACKAGE: dict[str, str] = {
    "openblas": "numpy",
    "libopenblas": "numpy",
    "scipy_openblas": "scipy",
    "libscipy_openblas": "scipy",
    "lapack": "scipy",
    "liblapack": "scipy",
    "libgfortran": "scipy",
    "gfortran": "scipy",
    "libquadmath": "scipy",
    "quadmath": "scipy",
    "libgomp": "scipy",
    "gomp": "scipy",
    "libfftw3": "scipy",
    "fftw": "scipy",
    "libqhull": "scipy",
    "qhull": "scipy",
    "libsuperlu": "scipy",
    "superlu": "scipy",
    "libarpack": "scipy",
    "arpack": "scipy",
    "libhighs": "scipy",
    "highs": "scipy",
    "libumfpack": "scipy",
    "libcholmod": "scipy",
    "libsuitesparseconfig": "scipy",
    "libcolamd": "scipy",
    "libamd": "scipy",
    "suitesparse": "scipy",
    "libpng": "pillow",
    "png": "pillow",
    "libjpeg": "pillow",
    "jpeg": "pillow",
    "libtiff": "pillow",
    "tiff": "pillow",
    "libwebp": "pillow",
    "webp": "pillow",
    "liblcms2": "pillow",
    "lcms2": "pillow",
    "libopencv": "cv2",
    "opencv": "cv2",
    "torch": "torch",
    "libtorch": "torch",
    "c10": "torch",
    "libc10": "torch",
    "torch_cpu": "torch",
    "libtorch_cpu": "torch",
    "torch_cuda": "torch",
    "libtorch_cuda": "torch",
    "arrow": "pyarrow",
    "libarrow": "pyarrow",
    "parquet": "pyarrow",
    "libparquet": "pyarrow",
    "geos": "shapely",
    "libgeos": "shapely",
    "geos_c": "shapely",
    "libgeos_c": "shapely",
}

# Known Python packages that frequently vendor native compiled binaries
KNOWN_PYTHON_PACKAGES: set[str] = {
    "numpy",
    "scipy",
    "pillow",
    "cv2",
    "opencv-python",
    "opencv-python-headless",
    "cryptography",
    "torch",
    "torchvision",
    "torchaudio",
    "matplotlib",
    "pandas",
    "sklearn",
    "scikit-learn",
    "pyarrow",
    "shapely",
    "cffi",
    "zstandard",
    "pyyaml",
    "grpcio",
    "grpc",
    "msgpack",
    "lxml",
    "psycopg2",
    "pycryptodome",
    "pynacl",
    "pyopenssl",
}


def normalize_single_license(raw: str) -> str:
    """Normalise a single licence token to its canonical SPDX identifier."""
    cleaned = raw.strip().strip("()").strip()
    if not cleaned or cleaned.lower() in {"unknown", "none", "noassertion"}:
        return "NOASSERTION"

    lower = cleaned.lower()
    if lower.startswith("licenseref-"):
        suffix = cleaned.split("-", 1)[1] if "-" in cleaned else cleaned[11:]
        return f"LicenseRef-{suffix}"

    if lower in RAW_TO_SPDX:
        return RAW_TO_SPDX[lower]

    for classifier, spdx in TROVE_CLASSIFIER_MAP.items():
        if lower == classifier.lower():
            return spdx

    all_known = (
        PERMISSIVE_SPDX
        | PUBLIC_DOMAIN_SPDX
        | WEAK_COPYLEFT_SPDX
        | STRONG_COPYLEFT_SPDX
        | {"LicenseRef-Proprietary"}
    )
    for known in all_known:
        if lower == known.lower():
            return known

    # Use license-expression library to validate and canonicalise SPDX identifiers and WITH exceptions
    try:
        parsed = _SPDX_LICENSING.parse(cleaned, validate=True)
        if isinstance(parsed, (LicenseSymbol, LicenseWithExceptionSymbol)):
            rendered = parsed.render()
            if "gcc" in rendered.lower() and "gpl-3.0" in rendered.lower():
                return "GPL-3.0-with-GCC-exception"
            return rendered
    except ExpressionError:
        pass

    # Handle SPDX WITH exceptions with non-canonical base names
    with_match = re.match(r"^(.+?)\s+WITH\s+([A-Za-z0-9.-]+)$", cleaned, flags=re.IGNORECASE)
    if with_match:
        base_part = with_match.group(1).strip()
        exc_part = with_match.group(2).strip()
        if "gcc" in exc_part.lower() and "gpl" in base_part.lower():
            return "GPL-3.0-with-GCC-exception"
        base_norm = normalize_single_license(base_part)
        if base_norm != "NOASSERTION":
            if "llvm" in exc_part.lower():
                return f"{base_norm} WITH LLVM-exception"
            return f"{base_norm} WITH {exc_part}"

    # Word-boundary and heuristic regex matching for verbose licence strings
    if re.search(r"\b(?:affero|agpl)\b", lower):
        return "AGPL-3.0-or-later"
    if "lesser general public" in lower or re.search(r"\blgpl\b", lower):
        if "3" in lower:
            return "LGPL-3.0-or-later" if "+" in lower or "later" in lower else "LGPL-3.0-only"
        return "LGPL-2.1-or-later" if "+" in lower or "later" in lower else "LGPL-2.1-only"
    if ("general public license" in lower or re.search(r"\bgpl\b", lower)) and "compatible" not in lower:
        if "gcc" in lower and "exception" in lower:
            return "GPL-3.0-with-GCC-exception"
        if "2" in lower:
            return "GPL-2.0-or-later" if "+" in lower or "later" in lower else "GPL-2.0-only"
        return "GPL-3.0-or-later" if "+" in lower or "later" in lower else "GPL-3.0-only"
    if "mozilla public license" in lower or re.search(r"\bmpl\b", lower):
        return "MPL-2.0"
    if "apache" in lower:
        if "1.1" in lower:
            return "Apache-1.1"
        if "1.0" in lower:
            return "Apache-1.0"
        return "Apache-2.0"
    if re.search(r"\bbsd\b", lower):
        if re.search(r"\b(?:0|zero)[-\s]*clause\b", lower) or "0bsd" in lower:
            return "0BSD"
        if re.search(r"\b(?:2|two)[-\s]*clause\b", lower) or "simplified" in lower or "freebsd" in lower:
            return "BSD-2-Clause"
        return "BSD-3-Clause"
    if re.search(r"\bmit\b", lower):
        return "MIT"
    if re.search(r"\bisc\b", lower):
        return "ISC"
    if "python software foundation" in lower or re.search(r"\bpsf\b", lower):
        return "PSF-2.0"
    if "unlicense" in lower:
        return "Unlicense"
    if "public domain" in lower:
        return "Public-Domain"

    # Corporate and internal licence patterns (e.g. "Acme Corp Internal Licence")
    internal_match = re.search(r"\b(?:([A-Za-z0-9_ -]+?)\s+)?internal\s+licen[cs]e\b", cleaned, re.IGNORECASE)
    if internal_match:
        prefix = (internal_match.group(1) or "").strip()
        cleaned_prefix = re.sub(r"^(?:the|an|a|our)\s+", "", prefix, flags=re.IGNORECASE).strip()
        if cleaned_prefix:
            slug = "-".join(part for part in re.split(r"[\s_-]+", cleaned_prefix) if part)
            return f"LicenseRef-{slug}-Internal"
        return "LicenseRef-Internal"

    if "internal" in lower and ("proprietary" in lower or "confidential" in lower or "rights reserved" in lower):
        return "LicenseRef-Internal"

    if "proprietary" in lower or "commercial" in lower:
        return "LicenseRef-Proprietary"

    return "NOASSERTION"


def _infer_spdx_from_section(section: str) -> str:
    """Infer an SPDX identifier from a licence text section."""
    lower = section.lower()
    if "apache license" in lower and "version 2.0" in lower:
        return "Apache-2.0"
    if "gnu affero general public license" in lower:
        return "AGPL-3.0-or-later"
    if "gnu lesser general public license" in lower:
        if "version 3" in lower:
            return "LGPL-3.0-or-later"
        return "LGPL-2.1-or-later"
    if "gnu general public license" in lower:
        if "runtime library exception" in lower:
            return "GPL-3.0-with-GCC-exception"
        if "version 2" in lower:
            return "GPL-2.0-or-later"
        return "GPL-3.0-or-later"
    if "mozilla public license" in lower and "version 2.0" in lower:
        return "MPL-2.0"
    if "permission is hereby granted, free of charge, to any person obtaining a copy" in lower:
        return "MIT"
    if "permission to use, copy, modify, and/or distribute this software for any purpose" in lower:
        if "above copyright notice and this permission notice appear in all copies" in lower:
            return "ISC"
        return "0BSD"
    if "redistribution and use in source and binary forms, with or without" in lower:
        if "neither the name of" in lower or "endorse or promote products" in lower:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "python software foundation license version 2" in lower:
        return "PSF-2.0"
    if "this is free and unencumbered software released into the public domain" in lower:
        return "Unlicense"

    # Corporate and internal licence patterns (e.g. "Acme Corp Internal Licence. All rights reserved.")
    internal_match = re.search(r"\b(?:([A-Za-z0-9_ -]+?)\s+)?internal\s+licen[cs]e\b", section, re.IGNORECASE)
    if internal_match:
        prefix = (internal_match.group(1) or "").strip()
        cleaned_prefix = re.sub(r"^(?:the|an|a|our)\s+", "", prefix, flags=re.IGNORECASE).strip()
        if cleaned_prefix:
            slug = "-".join(part for part in re.split(r"[\s_-]+", cleaned_prefix) if part)
            return f"LicenseRef-{slug}-Internal"
        return "LicenseRef-Internal"

    if (
        ("all rights reserved" in lower and ("internal" in lower or "proprietary" in lower or "confidential" in lower))
        or "proprietary and confidential" in lower
        or "for internal use only" in lower
    ):
        return "LicenseRef-Proprietary"

    return "NOASSERTION"


def infer_spdx_from_license_text(text: str) -> str:
    """Infer an SPDX identifier from verbatim licence file contents when metadata is missing."""
    if not text:
        return "NOASSERTION"
    # For multi-section licence files (e.g. NumPy/SciPy LICENSE.txt with bundled third-party appendices),
    # inspect the primary header section before any ==== or ---- divider first.
    primary_section = re.split(r"\n\s*(?:={4,}|-{4,})\s*\n", text, maxsplit=1)[0]
    if primary_section != text:
        header_match = _infer_spdx_from_section(primary_section)
        if header_match != "NOASSERTION":
            return header_match
    if len(text) > 1500:
        header_match = _infer_spdx_from_section(text[:1500])
        if header_match != "NOASSERTION":
            return header_match
    return _infer_spdx_from_section(text)


def classify_single_spdx(spdx_id: str) -> LicenseRiskCategory:
    """Classify a single normalised SPDX identifier into a legal risk category."""
    if not spdx_id or spdx_id in {"NOASSERTION", "UNKNOWN"}:
        return LicenseRiskCategory.UNKNOWN
    if " WITH " in spdx_id:
        base_id, exc_id = spdx_id.split(" WITH ", 1)
        exc_lower = exc_id.lower()
        if "llvm" in exc_lower or "gcc" in exc_lower or "autoconf" in exc_lower or "bison" in exc_lower:
            return LicenseRiskCategory.PERMISSIVE
        if "classpath" in exc_lower:
            return LicenseRiskCategory.WEAK_COPYLEFT
        return classify_single_spdx(base_id.strip())
    if spdx_id in PUBLIC_DOMAIN_SPDX:
        return LicenseRiskCategory.PUBLIC_DOMAIN
    if spdx_id in PERMISSIVE_SPDX:
        return LicenseRiskCategory.PERMISSIVE
    if spdx_id in WEAK_COPYLEFT_SPDX:
        return LicenseRiskCategory.WEAK_COPYLEFT
    if spdx_id in STRONG_COPYLEFT_SPDX:
        return LicenseRiskCategory.STRONG_COPYLEFT
    if (
        spdx_id == "LicenseRef-Proprietary"
        or "proprietary" in spdx_id.lower()
        or "intel" in spdx_id.lower()
        or "commercial" in spdx_id.lower()
        or "internal" in spdx_id.lower()
        or "corporate" in spdx_id.lower()
        or spdx_id.startswith("LicenseRef-")
    ):
        return LicenseRiskCategory.PROPRIETARY
    return LicenseRiskCategory.UNKNOWN


def _evaluate_spdx_ast(
    parsed_expr: Any,
) -> tuple[str, LicenseRiskCategory, bool, list[str]] | None:
    """
    Evaluate an SPDX expression AST parsed by `license_expression` (`AND`, `OR`, `LicenseSymbol`).
    Returns `(formatted_expression, effective_risk_category, is_dual_licensed, leaf_choices)`.
    """
    leaf_choices: list[str] = []

    def _walk(node: Any) -> tuple[str, LicenseRiskCategory, bool] | None:
        if isinstance(node, OR):
            children = [_walk(arg) for arg in node.args]
            if any(c is None for c in children):
                return None
            valid = [c for c in children if c is not None]
            expr_str = " OR ".join(f"({c[0]})" if " AND " in c[0] else c[0] for c in valid)
            best_cat = min((c[1] for c in valid), key=lambda cat: RISK_SEVERITY_ORDER[cat])
            return expr_str, best_cat, True
        if isinstance(node, AND):
            children = [_walk(arg) for arg in node.args]
            if any(c is None for c in children):
                return None
            valid = [c for c in children if c is not None]
            expr_str = " AND ".join(f"({c[0]})" if c[2] or " OR " in c[0] else c[0] for c in valid)
            worst_cat = max((c[1] for c in valid), key=lambda cat: RISK_SEVERITY_ORDER[cat])
            return expr_str, worst_cat, False
        if isinstance(node, (LicenseSymbol, LicenseWithExceptionSymbol)):
            norm = normalize_single_license(node.render())
            if norm == "NOASSERTION":
                return None
            if norm not in leaf_choices:
                leaf_choices.append(norm)
            return norm, classify_single_spdx(norm), False
        return None

    res = _walk(parsed_expr)
    if res is None or not leaf_choices:
        return None
    if len(leaf_choices) == 1:
        only = leaf_choices[0]
        return only, classify_single_spdx(only), False, leaf_choices
    return res[0], res[1], res[2], leaf_choices


def _normalize_compound_leaves(expr: str, *, allow_unknown: bool = False) -> str | None:
    """
    Normalise leaf clauses between parentheses and AND/OR operators so multi-word
    licence names (e.g. 'MIT License AND GPLv3') parse cleanly via `license_expression`.
    """
    cleaned = re.sub(r"^(?:dual(?:\s+licen[cs]ed?)?|licen[cs]es?)\s*:\s*", "", expr.strip(), flags=re.IGNORECASE)
    if "://" not in cleaned and cleaned.lower() not in RAW_TO_SPDX:
        cleaned = re.sub(r"\s*/\s*", " OR ", cleaned)
    else:
        cleaned = re.sub(r"\s+/\s+", " OR ", cleaned)

    raw_tokens = re.split(r"(\(|\)|\bAND\b|\bOR\b)", cleaned, flags=re.IGNORECASE)
    out_tokens: list[str] = []
    for tok in raw_tokens:
        stripped = tok.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if stripped in ("(", ")"):
            out_tokens.append(stripped)
        elif upper in ("AND", "OR"):
            out_tokens.append(upper)
        else:
            norm = normalize_single_license(stripped)
            if norm == "NOASSERTION":
                if not allow_unknown:
                    return None
                safe_tok = re.sub(r"\s+", "-", stripped)
                out_tokens.append(safe_tok)
            else:
                out_tokens.append(norm)
    return " ".join(out_tokens) if out_tokens else None


def _parse_compound_spdx(expr: str) -> tuple[str, LicenseRiskCategory, bool, list[str]] | None:
    """Parse a compound SPDX expression using `license_expression`."""
    norm_expr = _normalize_compound_leaves(expr, allow_unknown=False)
    if not norm_expr:
        return None
    try:
        parsed_ast = _SPDX_LICENSING.parse(norm_expr, validate=False)
    except ExpressionError:
        return None
    if not isinstance(parsed_ast, (AND, OR)):
        return None
    return _evaluate_spdx_ast(parsed_ast)


def parse_spdx_expression(
    raw_expression: str,
    classifiers: list[str] | None = None,
    license_texts: dict[str, str] | None = None,
) -> tuple[str, LicenseRiskCategory, bool, list[str]]:
    """
    Parse and normalise a raw licence string or expression, returning:
    `(normalised_spdx_expression, effective_risk_category, is_dual_licensed, choices)`.
    """
    candidates: list[str] = []
    if raw_expression and raw_expression.strip() and raw_expression.strip().upper() not in {"UNKNOWN", "NONE"}:
        expr = raw_expression.strip()
        if "\n" in expr or len(expr) > 120:
            first_line = expr.splitlines()[0].strip()
            first_norm = normalize_single_license(first_line)
            if first_norm != "NOASSERTION":
                candidates.append(first_norm)
            else:
                inferred_header = infer_spdx_from_license_text(expr)
                if inferred_header != "NOASSERTION":
                    candidates.append(inferred_header)
        else:
            is_slash_compound = (
                "/" in expr
                and "://" not in expr
                and expr.lower() not in RAW_TO_SPDX
                and not expr.startswith("License ::")
            )
            is_compound_syntax = bool(re.search(r"\b(?:OR|AND)\b", expr, flags=re.IGNORECASE)) or is_slash_compound
            if is_compound_syntax:
                parsed_compound = _parse_compound_spdx(expr)
                if parsed_compound is not None:
                    return parsed_compound
            else:
                single = normalize_single_license(expr)
                if single != "NOASSERTION":
                    candidates.append(single)

    if classifiers:
        for clf in classifiers:
            clf_clean = clf.strip()
            if clf_clean in TROVE_CLASSIFIER_MAP:
                mapped = TROVE_CLASSIFIER_MAP[clf_clean]
                if mapped not in candidates:
                    candidates.append(mapped)
            elif clf_clean.startswith("License ::"):
                tail = clf_clean.split("::")[-1].strip()
                norm = normalize_single_license(tail)
                if norm != "NOASSERTION" and norm not in candidates:
                    candidates.append(norm)

    if not candidates and license_texts:
        sorted_texts = sorted(
            license_texts.items(),
            key=lambda kv: (1 if "bundled" in kv[0].lower() or "third" in kv[0].lower() else 0, kv[0].lower()),
        )
        for _fname, text in sorted_texts:
            inferred = infer_spdx_from_license_text(text)
            if inferred != "NOASSERTION":
                candidates.append(inferred)
                break

    if not candidates:
        return "NOASSERTION", LicenseRiskCategory.UNKNOWN, False, []

    if len(candidates) == 1:
        spdx_id = candidates[0]
        return spdx_id, classify_single_spdx(spdx_id), False, [spdx_id]

    raw_lower = (raw_expression or "").lower()
    if " and " in raw_lower:
        spdx_expr = " AND ".join(candidates)
        worst_cat = max((classify_single_spdx(c) for c in candidates), key=lambda c: RISK_SEVERITY_ORDER[c])
        return spdx_expr, worst_cat, False, candidates

    if " or " in raw_lower or "/" in raw_lower:
        spdx_expr = " OR ".join(candidates)
        best_cat = min((classify_single_spdx(c) for c in candidates), key=lambda c: RISK_SEVERITY_ORDER[c])
        return spdx_expr, best_cat, True, candidates

    # When multiple distinct licenses are declared without explicit 'and', treat as dual-licensed (OR) choice per PEP 639
    spdx_expr = " OR ".join(candidates)
    best_cat = min((classify_single_spdx(c) for c in candidates), key=lambda c: RISK_SEVERITY_ORDER[c])
    return spdx_expr, best_cat, True, candidates


def evaluate_spdx_allowlist(spdx_expr: str, allowed_upper: set[str]) -> bool:
    """
    Evaluate whether an SPDX licence expression is satisfied by a set of allowed licences (uppercase)
    using `license_expression` AST traversal.
    """
    if not spdx_expr:
        return False
    if spdx_expr.upper() in allowed_upper:
        return True

    norm_expr = _normalize_compound_leaves(spdx_expr, allow_unknown=True) or spdx_expr
    try:
        parsed_ast = _SPDX_LICENSING.parse(norm_expr, validate=False)
    except ExpressionError:
        norm = normalize_single_license(spdx_expr)
        return norm.upper() in allowed_upper

    if parsed_ast is None:
        return False

    def _eval_node(node: Any) -> bool:
        if isinstance(node, OR):
            return any(_eval_node(arg) for arg in node.args)
        if isinstance(node, AND):
            return all(_eval_node(arg) for arg in node.args)
        if isinstance(node, (LicenseSymbol, LicenseWithExceptionSymbol)):
            raw_tok = node.render()
            norm = normalize_single_license(raw_tok)
            return norm.upper() in allowed_upper or raw_tok.upper() in allowed_upper
        return False

    return _eval_node(parsed_ast)


def evaluate_spdx_denylist(spdx_expr: str, denied_upper: set[str]) -> bool:
    """
    Evaluate whether an SPDX licence expression violates a set of denied licences (uppercase)
    using `license_expression` AST traversal:
    - For conjunctive `AND`: violated if ANY required operand is denied.
    - For disjunctive `OR`: violated if ALL choices are denied.
    """
    if not spdx_expr or not denied_upper:
        return False
    if spdx_expr.upper() in denied_upper:
        return True

    norm_expr = _normalize_compound_leaves(spdx_expr, allow_unknown=True) or spdx_expr
    try:
        parsed_ast = _SPDX_LICENSING.parse(norm_expr, validate=False)
    except ExpressionError:
        norm = normalize_single_license(spdx_expr)
        return norm.upper() in denied_upper

    if parsed_ast is None:
        return False

    def _is_denied(node: Any) -> bool:
        if isinstance(node, OR):
            return all(_is_denied(arg) for arg in node.args)
        if isinstance(node, AND):
            return any(_is_denied(arg) for arg in node.args)
        if isinstance(node, (LicenseSymbol, LicenseWithExceptionSymbol)):
            raw_tok = node.render()
            norm = normalize_single_license(raw_tok)
            return norm.upper() in denied_upper or raw_tok.upper() in denied_upper
        return False

    return _is_denied(parsed_ast)


COPYRIGHT_LINE_RE = re.compile(
    r"^(?:[\s*#;-]*)(copyright\s*(?:\([cC]\)|©)?\s*\d{4}[^\r\n]*|©\s*\d{4}[^\r\n]*|\([cC]\)\s*\d{4}[^\r\n]*)",
    re.IGNORECASE | re.MULTILINE,
)


def extract_copyright_notices(
    license_texts: dict[str, str],
    author: str = "",
    author_email: str = "",
) -> list[str]:
    """Extract distinct copyright lines from verbatim licence texts, with author metadata fallback."""
    notices: list[str] = []
    seen_lower: set[str] = set()

    for text in license_texts.values():
        for match in COPYRIGHT_LINE_RE.finditer(text):
            line = " ".join(match.group(1).strip().split())
            if "[year]" in line.lower() or "<year>" in line.lower() or "yyyy" in line.lower():
                continue
            if len(line) > 180:
                line = line[:180].rstrip()
            norm = line.lower()
            if norm not in seen_lower:
                seen_lower.add(norm)
                notices.append(line)

    if author or author_email:
        parts = [
            p.strip()
            for p in (
                author,
                f"<{author_email}>" if author_email and "<" not in author_email else author_email,
            )
            if p and p.strip()
        ]
        if parts:
            author_line = f"Copyright (c) {' '.join(parts)}"
            author_token = author.lower().strip() if author else author_email.lower().strip()
            if not any(author_token in n.lower() for n in notices):
                notices.append(author_line)

    return notices


def build_license_info(
    declared_raw: str = "",
    license_expression: str = "",
    classifiers: list[str] | None = None,
    license_texts: dict[str, str] | None = None,
    notice_texts: dict[str, str] | None = None,
    author: str = "",
    author_email: str = "",
) -> LicenseInfo:
    """Construct a complete LicenseInfo object from package metadata and files."""
    effective_raw = (
        license_expression.strip()
        if license_expression and license_expression.strip()
        else declared_raw.strip()
    )
    texts = license_texts or {}
    notices_map = notice_texts or {}
    spdx_id, risk_category, is_dual, choices = parse_spdx_expression(
        effective_raw,
        classifiers=classifiers,
        license_texts=texts,
    )
    copyrights = extract_copyright_notices(texts, author=author, author_email=author_email)
    return LicenseInfo(
        declared_raw=effective_raw or (classifiers[0] if classifiers else "UNKNOWN"),
        spdx_id=spdx_id,
        risk_category=risk_category,
        copyright_notices=copyrights,
        license_texts=dict(texts),
        notice_texts=dict(notices_map),
        is_dual_licensed=is_dual,
        license_choices=choices,
    )
